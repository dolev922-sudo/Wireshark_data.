"""Data models shared by every part of the analyzer.

Everything the dashboard shows is stored in one of these plain dataclasses.
Keeping them in one file makes it easy to see exactly which facts the engine
extracts from a capture - and therefore which facts the AI assistant is allowed
to talk about.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional

# How confident we are in the protocol label of a packet.
ID_CONTENT = "content"      # payload bytes were inspected and matched the protocol
ID_HEADER = "header"        # identified from a lower-layer header field (ARP, ICMP...)
ID_PORT = "port"            # guessed from a well-known port only (not verified)
ID_TRANSPORT = "transport"  # only the transport protocol is known (plain TCP/UDP)
ID_UNKNOWN = "unknown"      # could not be decoded / unsupported


@dataclass(slots=True)
class PacketRecord:
    """One captured frame, decoded down to the transport layer."""

    frame: int                    # 1-based position in the file (same as Wireshark's frame.number)
    timestamp: float              # seconds since the Unix epoch
    captured_length: int          # bytes stored in the file
    wire_length: int              # bytes that were on the wire
    link_type: int
    src_mac: str = ""
    dst_mac: str = ""
    ethertype: Optional[int] = None
    ip_version: Optional[int] = None
    src_ip: str = ""
    dst_ip: str = ""
    ttl: Optional[int] = None
    ip_protocol: Optional[int] = None   # IANA protocol number (6 = TCP, 17 = UDP ...)
    transport: str = ""                 # "TCP", "UDP", "ICMP", "ICMPv6", "ARP" or ""
    src_port: Optional[int] = None
    dst_port: Optional[int] = None
    tcp_seq: Optional[int] = None
    tcp_ack: Optional[int] = None
    tcp_flags: int = 0
    tcp_window: Optional[int] = None
    payload_offset: int = 0             # where the transport payload starts inside the frame
    payload_length: int = 0             # transport payload bytes present in this frame
    protocol: str = "Unknown"           # label shown in the dashboard
    identification: str = ID_UNKNOWN    # one of the ID_* constants above
    info: str = ""                      # short human readable summary
    stream_id: Optional[int] = None     # TCP stream index (same numbering idea as tcp.stream)
    tcp_analysis: str = ""              # "retransmission", "out-of-order" or ""
    decode_error: str = ""              # non-empty when the frame is truncated / malformed


@dataclass(slots=True)
class StreamPiece:
    """A run of reassembled bytes that came from a single frame."""

    offset: int        # position inside the reassembled direction stream
    length: int
    frame: int
    timestamp: float


@dataclass
class DirectionStream:
    """Reassembled bytes flowing one way on a TCP connection.

    A direction is stored as one or more *contiguous chunks*. When bytes are
    missing from the capture (a gap), a new chunk begins after the gap, so we
    never glue unrelated bytes together.
    """

    src_ip: str
    src_port: int
    dst_ip: str
    dst_port: int
    chunks: list[bytes] = field(default_factory=list)
    chunk_pieces: list[list[StreamPiece]] = field(default_factory=list)
    gap_bytes: int = 0                 # bytes known to be missing between chunks
    payload_frames: int = 0
    payload_bytes: int = 0
    retransmitted_frames: list[int] = field(default_factory=list)
    out_of_order_frames: list[int] = field(default_factory=list)
    syn_frame: Optional[int] = None
    fin_frame: Optional[int] = None
    rst_frame: Optional[int] = None
    starts_mid_stream: bool = False    # no SYN seen: the capture began after the connection


@dataclass
class TcpStream:
    """One TCP connection (both directions)."""

    stream_id: int
    client: DirectionStream            # the side that sent the first packet / SYN
    server: DirectionStream
    first_frame: int = 0
    last_frame: int = 0
    first_timestamp: float = 0.0
    last_timestamp: float = 0.0
    frames: list[int] = field(default_factory=list)
    handshake_complete: bool = False   # SYN, SYN-ACK and the final ACK were all captured
    app_protocol: str = ""             # "HTTP", "TLS" or ""

    @property
    def has_gaps(self) -> bool:
        return self.client.gap_bytes > 0 or self.server.gap_bytes > 0

    @property
    def is_partial(self) -> bool:
        """True when we know that we did not capture the whole conversation."""
        return self.has_gaps or self.client.starts_mid_stream or self.server.starts_mid_stream

    @property
    def retransmissions(self) -> int:
        return len(self.client.retransmitted_frames) + len(self.server.retransmitted_frames)

    @property
    def out_of_order(self) -> int:
        return len(self.client.out_of_order_frames) + len(self.server.out_of_order_frames)

    def label(self) -> str:
        c, s = self.client, self.server
        return f"{c.src_ip}:{c.src_port} -> {s.src_ip}:{s.src_port}"


@dataclass
class HttpMessage:
    """A single HTTP/1.x request or response found in a reassembled stream."""

    is_request: bool
    start_line: str
    version: str = ""
    method: str = ""
    uri: str = ""
    status_code: Optional[int] = None
    reason: str = ""
    headers: list[tuple[str, str]] = field(default_factory=list)
    body_length: int = 0               # body bytes actually captured
    declared_length: Optional[int] = None
    framing: str = "none"              # "none", "content-length", "chunked", "until-close"
    complete: bool = True
    first_frame: int = 0               # frame carrying the first byte of the message
    last_frame: int = 0                # frame carrying the last byte (Wireshark shows the message here)
    first_timestamp: float = 0.0
    last_timestamp: float = 0.0
    frames: list[int] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)

    def header(self, name: str) -> str:
        """Return the first header with this (case-insensitive) name, or ''."""
        wanted = name.lower()
        for key, value in self.headers:
            if key.lower() == wanted:
                return value
        return ""


@dataclass
class HttpTransaction:
    """A request paired with its response (or flagged as missing one)."""

    transaction_id: str                # stable identifier such as "T0007"
    stream_id: int
    index_in_stream: int               # 1 = first request on this connection
    client_ip: str
    client_port: int
    server_ip: str
    server_port: int
    request: Optional[HttpMessage]
    response: Optional[HttpMessage]
    informational: list[HttpMessage] = field(default_factory=list)  # 1xx responses
    match_confidence: str = "none"     # "confirmed", "uncertain" or "none"
    warnings: list[str] = field(default_factory=list)

    # ---- convenience accessors used by tables, tests and the AI context ----
    @property
    def method(self) -> str:
        return self.request.method if self.request else ""

    @property
    def host(self) -> str:
        return self.request.header("Host") if self.request else ""

    @property
    def uri(self) -> str:
        return self.request.uri if self.request else ""

    @property
    def status_code(self) -> Optional[int]:
        return self.response.status_code if self.response else None

    @property
    def request_frame(self) -> Optional[int]:
        """Frame where the complete request is visible (Wireshark convention)."""
        return self.request.last_frame if self.request else None

    @property
    def request_timestamp(self) -> Optional[float]:
        return self.request.last_timestamp if self.request else None

    @property
    def response_frame(self) -> Optional[int]:
        """Frame that completes the response (Wireshark's default HTTP row)."""
        return self.response.last_frame if self.response else None

    @property
    def response_timestamp(self) -> Optional[float]:
        return self.response.last_timestamp if self.response else None

    @property
    def response_first_frame(self) -> Optional[int]:
        return self.response.first_frame if self.response else None

    @property
    def response_time(self) -> Optional[float]:
        """Seconds from the request frame to the frame completing the response.

        This follows Wireshark's ``http.time`` ("time since request").
        """
        if self.request is None or self.response is None:
            return None
        return self.response.last_timestamp - self.request.last_timestamp

    @property
    def time_to_first_byte(self) -> Optional[float]:
        """Seconds from the request frame to the first response byte."""
        if self.request is None or self.response is None:
            return None
        return self.response.first_timestamp - self.request.last_timestamp

    @property
    def is_complete(self) -> bool:
        return (
            self.request is not None
            and self.response is not None
            and self.request.complete
            and self.response.complete
        )


@dataclass
class TlsSession:
    """Metadata of an encrypted (HTTPS/TLS) connection.

    The content is encrypted, so only handshake metadata is available.
    """

    stream_id: int
    client_ip: str
    client_port: int
    server_ip: str
    server_port: int
    server_name: str = ""              # SNI from the ClientHello ("" when absent)
    client_hello_frame: Optional[int] = None
    server_hello_frame: Optional[int] = None
    client_hello_timestamp: Optional[float] = None
    server_hello_timestamp: Optional[float] = None
    tls_version: str = ""              # negotiated version if the ServerHello was seen
    alpn: list[str] = field(default_factory=list)
    client_bytes: int = 0
    server_bytes: int = 0

    @property
    def handshake_time(self) -> Optional[float]:
        if self.client_hello_timestamp is None or self.server_hello_timestamp is None:
            return None
        return self.server_hello_timestamp - self.client_hello_timestamp


@dataclass
class CaptureAnalysis:
    """Everything extracted from one uploaded capture file."""

    file_name: str
    file_size: int
    file_format: str                   # "pcap" or "pcapng"
    sha256: str
    packets: list[PacketRecord] = field(default_factory=list)
    raw_frames: list[bytes] = field(default_factory=list)   # raw bytes, index = frame - 1
    streams: list[TcpStream] = field(default_factory=list)
    transactions: list[HttpTransaction] = field(default_factory=list)
    tls_sessions: list[TlsSession] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)       # problems found while reading

    @property
    def packet_count(self) -> int:
        return len(self.packets)

    @property
    def start_time(self) -> Optional[float]:
        return min((p.timestamp for p in self.packets), default=None)

    @property
    def end_time(self) -> Optional[float]:
        return max((p.timestamp for p in self.packets), default=None)

    @property
    def duration(self) -> float:
        if not self.packets:
            return 0.0
        return float(self.end_time - self.start_time)

    def packet(self, frame: int) -> Optional[PacketRecord]:
        if 1 <= frame <= len(self.packets):
            return self.packets[frame - 1]
        return None

    def transaction(self, transaction_id: str) -> Optional[HttpTransaction]:
        for transaction in self.transactions:
            if transaction.transaction_id == transaction_id:
                return transaction
        return None

    def stream(self, stream_id: int) -> Optional[TcpStream]:
        if 0 <= stream_id < len(self.streams):
            return self.streams[stream_id]
        return None
