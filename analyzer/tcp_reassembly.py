"""TCP stream reconstruction.

Why this is needed
------------------
HTTP runs on top of TCP, and TCP is a *byte stream*: one HTTP message may be
split over many packets, packets may arrive twice (retransmission) or in the
wrong order, and some may be missing from the capture. Before HTTP can be
parsed reliably, the bytes of each direction of each connection must be put
back in order.

Algorithm
---------
1. **Group packets into connections.** Packets with the same two
   (IP, port) endpoints belong to the same connection. A new SYN with a
   different initial sequence number starts a *new* connection on the same
   ports (port reuse). Connections are numbered in order of appearance, the
   same idea as Wireshark's ``tcp.stream``.
2. **Convert sequence numbers to stream offsets.** The SYN's sequence number
   (ISN) + 1 is byte 0 of that direction. If the SYN was not captured, the
   lowest sequence number seen becomes byte 0 and the stream is flagged as
   "starts mid-stream".
3. **Place every segment by its sequence number, not by arrival order.**
   Segments are processed in arrival order; for each one we check which of
   its bytes are already known:
     * all bytes already known  -> *retransmission* (ignored, first copy wins)
     * fills a hole behind the highest byte seen -> *out-of-order* (accepted)
     * otherwise -> normal new data
4. **Split at gaps.** Bytes that never appear in the capture leave a hole.
   Instead of gluing the data around a hole together, the direction is split
   into separate contiguous *chunks* and the number of missing bytes is kept.
5. **Remember which frame supplied which bytes.** Every chunk keeps a list of
   (offset, length, frame, timestamp) pieces, so that later the HTTP parser
   can say exactly which frame carried the first and last byte of a message.
"""

from __future__ import annotations

from bisect import bisect_right
from dataclasses import dataclass, field
from typing import Optional

from .models import CaptureAnalysis, DirectionStream, PacketRecord, StreamPiece, TcpStream
from .parser import FLAG_ACK, FLAG_FIN, FLAG_RST, FLAG_SYN, tcp_flags_text

SEQ_MODULO = 1 << 32
SEQ_HALF = 1 << 31


def signed_sequence_distance(sequence: int, base: int) -> int:
    """Distance from ``base`` to ``sequence`` with 32-bit wrap-around handled."""
    return ((sequence - base + SEQ_HALF) % SEQ_MODULO) - SEQ_HALF


@dataclass
class _Segment:
    frame: int
    timestamp: float
    sequence: int
    length: int
    flags: int


@dataclass
class _DirectionBuilder:
    src_ip: str
    src_port: int
    dst_ip: str
    dst_port: int
    segments: list[_Segment] = field(default_factory=list)   # every packet of this direction
    syn_sequence: Optional[int] = None
    syn_frame: Optional[int] = None
    fin_frame: Optional[int] = None
    rst_frame: Optional[int] = None
    first_sequence: Optional[int] = None


@dataclass
class _StreamBuilder:
    stream_id: int
    forward: _DirectionBuilder      # direction of the first packet seen
    backward: _DirectionBuilder
    frames: list[int] = field(default_factory=list)
    closed: bool = False            # FIN or RST seen (used for port-reuse detection)


class _CoveredRanges:
    """Sorted, non-overlapping [start, end) ranges of bytes already received."""

    def __init__(self) -> None:
        self.starts: list[int] = []
        self.ends: list[int] = []

    def missing_parts(self, start: int, end: int) -> list[tuple[int, int]]:
        """Return the sub-ranges of [start, end) that are not covered yet."""
        missing = []
        index = max(0, bisect_right(self.starts, start) - 1)
        cursor = start
        while index < len(self.starts) and self.starts[index] < end:
            if self.ends[index] > cursor:
                if self.starts[index] > cursor:
                    missing.append((cursor, self.starts[index]))
                cursor = max(cursor, self.ends[index])
            index += 1
        if cursor < end:
            missing.append((cursor, end))
        return missing

    def add(self, start: int, end: int) -> None:
        index = bisect_right(self.starts, start)
        if index > 0 and self.ends[index - 1] >= start:         # merge with the range on the left
            index -= 1
            start = self.starts[index]
            end = max(end, self.ends[index])
            del self.starts[index], self.ends[index]
        while index < len(self.starts) and self.starts[index] <= end:   # merge ranges on the right
            end = max(end, self.ends[index])
            del self.starts[index], self.ends[index]
        self.starts.insert(index, start)
        self.ends.insert(index, end)


def reassemble_tcp_streams(analysis: CaptureAnalysis) -> list[TcpStream]:
    """Build ``analysis.streams`` from ``analysis.packets`` and return them."""
    builders: list[_StreamBuilder] = []
    active: dict[tuple, _StreamBuilder] = {}

    for packet in analysis.packets:
        if packet.transport != "TCP" or packet.tcp_seq is None:
            continue
        source, destination = (packet.src_ip, packet.src_port), (packet.dst_ip, packet.dst_port)
        key = (source, destination) if source <= destination else (destination, source)
        builder = active.get(key)
        is_pure_syn = bool(packet.tcp_flags & FLAG_SYN) and not packet.tcp_flags & FLAG_ACK

        if builder is not None and is_pure_syn and builder.frames:
            direction = builder.forward if (builder.forward.src_ip, builder.forward.src_port) == source else builder.backward
            if direction.syn_sequence != packet.tcp_seq:   # not just a retransmitted SYN
                builder = None                             # same ports reused: start a new stream
        if builder is None:
            builder = _StreamBuilder(
                stream_id=len(builders),
                forward=_DirectionBuilder(packet.src_ip, packet.src_port, packet.dst_ip, packet.dst_port),
                backward=_DirectionBuilder(packet.dst_ip, packet.dst_port, packet.src_ip, packet.src_port),
            )
            builders.append(builder)
            active[key] = builder

        direction = builder.forward if (builder.forward.src_ip, builder.forward.src_port) == source else builder.backward
        if direction.first_sequence is None:
            direction.first_sequence = packet.tcp_seq
        if packet.tcp_flags & FLAG_SYN and direction.syn_sequence is None:
            direction.syn_sequence, direction.syn_frame = packet.tcp_seq, packet.frame
        if packet.tcp_flags & FLAG_FIN and direction.fin_frame is None:
            direction.fin_frame = packet.frame
        if packet.tcp_flags & FLAG_RST and direction.rst_frame is None:
            direction.rst_frame = packet.frame
        direction.segments.append(
            _Segment(packet.frame, packet.timestamp, packet.tcp_seq, packet.payload_length, packet.tcp_flags))
        builder.frames.append(packet.frame)
        packet.stream_id = builder.stream_id

    analysis.streams = [_finish_stream(builder, analysis) for builder in builders]
    return analysis.streams


def _finish_stream(builder: _StreamBuilder, analysis: CaptureAnalysis) -> TcpStream:
    forward, backward = builder.forward, builder.backward
    # The client is the side that sent the SYN (without ACK). When no handshake
    # was captured we fall back to "whoever sent the first packet".
    forward_is_client = True
    forward_syn = _flags_of(analysis, forward.syn_frame)
    backward_syn = _flags_of(analysis, backward.syn_frame)
    if forward_syn is not None and forward_syn & FLAG_ACK and not (backward_syn is not None and backward_syn & FLAG_ACK):
        forward_is_client = False        # first packet seen was the server's SYN-ACK
    client_builder, server_builder = (forward, backward) if forward_is_client else (backward, forward)

    client = _assemble_direction(client_builder, analysis)
    server = _assemble_direction(server_builder, analysis)
    stream = TcpStream(
        stream_id=builder.stream_id, client=client, server=server,
        first_frame=builder.frames[0], last_frame=builder.frames[-1],
        first_timestamp=analysis.packets[builder.frames[0] - 1].timestamp,
        last_timestamp=analysis.packets[builder.frames[-1] - 1].timestamp,
        frames=builder.frames,
    )
    # Handshake = SYN, then SYN-ACK, then an ACK from the client.
    if client.syn_frame and server.syn_frame and server.syn_frame > client.syn_frame:
        stream.handshake_complete = any(
            segment.frame > server.syn_frame and segment.flags & FLAG_ACK and not segment.flags & FLAG_SYN
            for segment in client_builder.segments
        )
    _write_relative_info(analysis, client_builder, server_builder)
    return stream


def _flags_of(analysis: CaptureAnalysis, frame: Optional[int]) -> Optional[int]:
    return analysis.packets[frame - 1].tcp_flags if frame else None


def _initial_sequence(direction: _DirectionBuilder) -> Optional[int]:
    """Sequence number that corresponds to 'relative sequence number 0'."""
    if direction.syn_sequence is not None:
        return direction.syn_sequence
    if direction.first_sequence is not None:
        return (direction.first_sequence - 1) % SEQ_MODULO      # Wireshark convention: first byte = 1
    return None


def _assemble_direction(direction: _DirectionBuilder, analysis: CaptureAnalysis) -> DirectionStream:
    result = DirectionStream(
        src_ip=direction.src_ip, src_port=direction.src_port,
        dst_ip=direction.dst_ip, dst_port=direction.dst_port,
        syn_frame=direction.syn_frame, fin_frame=direction.fin_frame, rst_frame=direction.rst_frame,
    )
    data_segments = [segment for segment in direction.segments if segment.length > 0]
    result.starts_mid_stream = direction.syn_sequence is None and bool(direction.segments)
    if not data_segments:
        return result

    # --- step 2: sequence numbers -> stream offsets ---------------------------
    if direction.syn_sequence is not None:
        base = (direction.syn_sequence + 1) % SEQ_MODULO
        offsets = [signed_sequence_distance(segment.sequence, base) for segment in data_segments]
    else:
        base = data_segments[0].sequence
        offsets = [signed_sequence_distance(segment.sequence, base) for segment in data_segments]
        lowest = min(offsets)
        offsets = [offset - lowest for offset in offsets]          # earliest byte seen becomes offset 0

    # --- step 3: place segments, detect retransmissions / out-of-order --------
    covered = _CoveredRanges()
    highest_end = 0
    pieces: list[tuple[int, int, bytes, int, float]] = []   # (offset, length, data, frame, timestamp)
    for segment, offset in zip(data_segments, offsets):
        packet = analysis.packets[segment.frame - 1]
        result.payload_frames += 1
        result.payload_bytes += segment.length
        if offset < 0:      # data from before the SYN's sequence space: cannot be placed
            packet.tcp_analysis = "invalid-sequence"
            continue
        end = offset + segment.length
        missing = covered.missing_parts(offset, end)
        if not missing:
            is_keep_alive = segment.length == 1 and end == highest_end
            packet.tcp_analysis = "keep-alive" if is_keep_alive else "retransmission"
            if not is_keep_alive:
                result.retransmitted_frames.append(segment.frame)
            continue
        if offset < highest_end:
            if missing[0][0] < highest_end:
                packet.tcp_analysis = "out-of-order"       # fills a hole left by an earlier jump
                result.out_of_order_frames.append(segment.frame)
            else:
                packet.tcp_analysis = "retransmission"     # old bytes repeated together with new ones
                result.retransmitted_frames.append(segment.frame)
        raw = analysis.raw_frames[segment.frame - 1]
        payload = raw[packet.payload_offset:packet.payload_offset + packet.payload_length]
        for part_start, part_end in missing:
            pieces.append((part_start, part_end - part_start,
                           payload[part_start - offset:part_end - offset], segment.frame, segment.timestamp))
            covered.add(part_start, part_end)
        highest_end = max(highest_end, end)

    # --- step 4 + 5: build contiguous chunks and the byte -> frame map --------
    pieces.sort(key=lambda piece: piece[0])
    expected = 0 if direction.syn_sequence is not None else (pieces[0][0] if pieces else 0)
    chunk_data: list[bytes] = []
    chunk_map: list[StreamPiece] = []
    chunk_start = expected

    def close_chunk() -> None:
        if chunk_data:
            result.chunks.append(b"".join(chunk_data))
            result.chunk_pieces.append(list(chunk_map))
            chunk_data.clear()
            chunk_map.clear()

    for offset, length, data, frame, timestamp in pieces:
        if offset > expected:                 # hole: bytes missing from the capture
            result.gap_bytes += offset - expected
            close_chunk()
            chunk_start = offset
        elif not chunk_data:
            chunk_start = offset
        chunk_data.append(data)
        chunk_map.append(StreamPiece(offset - chunk_start, length, frame, timestamp))
        expected = offset + length
    close_chunk()
    return result


def _write_relative_info(analysis: CaptureAnalysis, client: _DirectionBuilder, server: _DirectionBuilder) -> None:
    """Rewrite the Info column with relative Seq/Ack numbers (like Wireshark)."""
    for direction, peer in ((client, server), (server, client)):
        own_base, peer_base = _initial_sequence(direction), _initial_sequence(peer)
        for segment in direction.segments:
            packet = analysis.packets[segment.frame - 1]
            relative_seq = (segment.sequence - own_base) % SEQ_MODULO if own_base is not None else segment.sequence
            text = f"{packet.src_port} → {packet.dst_port} [{tcp_flags_text(packet.tcp_flags)}] Seq={relative_seq}"
            if packet.tcp_flags & FLAG_ACK:
                relative_ack = (packet.tcp_ack - peer_base) % SEQ_MODULO if peer_base is not None else packet.tcp_ack
                text += f" Ack={relative_ack}"
            text += f" Win={packet.tcp_window} Len={packet.payload_length}"
            if packet.tcp_analysis:
                text = f"[TCP {packet.tcp_analysis.replace('-', ' ').title()}] " + text
            packet.info = text


def frame_at(pieces: list[StreamPiece], offset: int) -> StreamPiece:
    """Return the piece (and therefore the frame) that supplied byte ``offset``."""
    low, high = 0, len(pieces) - 1
    while low < high:
        middle = (low + high + 1) // 2
        if pieces[middle].offset <= offset:
            low = middle
        else:
            high = middle - 1
    return pieces[low]


def frames_between(pieces: list[StreamPiece], start: int, end: int) -> list[int]:
    """Frames that supplied bytes in [start, end), in stream order, without duplicates."""
    frames: list[int] = []
    for piece in pieces:
        if piece.offset + piece.length <= start:
            continue
        if piece.offset >= end:
            break
        if not frames or frames[-1] != piece.frame:
            frames.append(piece.frame)
    return frames


__all__ = [
    "reassemble_tcp_streams", "frame_at", "frames_between", "signed_sequence_distance", "PacketRecord",
]
