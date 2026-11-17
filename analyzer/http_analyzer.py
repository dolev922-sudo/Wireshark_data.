"""HTTP/1.x parsing, request/response matching and TLS (HTTPS) metadata.

How requests are matched to responses
-------------------------------------
Matching is done **per TCP connection, by position in the byte stream** - never
by "the response that is closest in time".

HTTP/1.1 guarantees that a server answers the requests of one connection in
the order they were sent (RFC 9112, section 9.3). So after reassembly we have,
for each connection, an ordered list of requests (client -> server bytes) and
an ordered list of responses (server -> client bytes), and:

    response number k  answers  request number k

Extra rules that keep the pairing honest:

* ``1xx`` informational responses (e.g. ``100 Continue``) do not answer a
  request; they are attached to the pending request and matching continues.
* A response that begins *before* the request at the head of the queue was sent
  cannot be its answer (cause must precede effect). It is reported as an
  "orphan response" - this happens when the capture started mid-connection.
* If bytes are missing from the capture (a gap), a request or response may be
  lost and the position rule is no longer provable. Pairs found after a gap
  are still shown, but marked **uncertain** with an explicit warning.
* Requests still waiting when the stream ends are reported as
  "no response captured" - nothing is invented.

Message boundaries (framing) follow the HTTP rules: ``Transfer-Encoding:
chunked`` first, then ``Content-Length``, otherwise requests have no body and
responses run until the connection closes. Responses to ``HEAD`` and
``1xx/204/304`` responses never have a body.
"""

from __future__ import annotations

import re
import struct
from bisect import bisect_right
from collections import deque
from dataclasses import dataclass
from typing import Optional

from .models import (
    ID_CONTENT,
    CaptureAnalysis,
    DirectionStream,
    HttpMessage,
    HttpTransaction,
    StreamPiece,
    TcpStream,
    TlsSession,
)

HTTP_METHODS = (
    "GET", "HEAD", "POST", "PUT", "DELETE", "CONNECT", "OPTIONS", "TRACE", "PATCH",
    "PROPFIND", "PROPPATCH", "MKCOL", "COPY", "MOVE", "LOCK", "UNLOCK", "REPORT", "SEARCH", "PURGE",
)
_REQUEST_PREFIXES = tuple(method.encode() + b" " for method in HTTP_METHODS)
_REQUEST_LINE = re.compile(rb"^([A-Z]{3,10}) (\S+) HTTP/(\d\.\d)$")
_STATUS_LINE = re.compile(rb"^HTTP/(\d\.\d) (\d{3})(?: (.*))?$")
MAX_START_LINE = 16 * 1024
TLS_VERSIONS = {0x0300: "SSL 3.0", 0x0301: "TLS 1.0", 0x0302: "TLS 1.1", 0x0303: "TLS 1.2", 0x0304: "TLS 1.3"}


@dataclass
class _Parsed:
    """An HttpMessage plus bookkeeping needed only while matching."""

    message: HttpMessage
    chunk_index: int        # 0 = before any gap in its direction


def _looks_like_request(data: bytes, position: int = 0) -> bool:
    return data.startswith(_REQUEST_PREFIXES, position)


def _looks_like_response(data: bytes, position: int = 0) -> bool:
    return data.startswith(b"HTTP/1.", position)


def _looks_like_http(data: bytes, position: int = 0) -> bool:
    return _looks_like_request(data, position) or _looks_like_response(data, position)


class _ChunkIndex:
    """Fast lookup from byte offsets of one contiguous chunk to frames."""

    def __init__(self, pieces: list[StreamPiece]) -> None:
        self.pieces = pieces
        self.offsets = [piece.offset for piece in pieces]

    def _range(self, start: int, end: int) -> list[StreamPiece]:
        first = max(0, bisect_right(self.offsets, start) - 1)
        last = bisect_right(self.offsets, max(start, end - 1))
        return self.pieces[first:last]

    def describe(self, message: HttpMessage, start: int, end: int) -> None:
        """Fill in which frames carried bytes [start, end) of the chunk."""
        pieces = self._range(start, end)
        first = pieces[0]
        # The message becomes complete when its *latest-arriving* frame shows up,
        # which is not always the frame holding its last byte (out-of-order data).
        completing = max(pieces, key=lambda piece: piece.frame)
        message.first_frame, message.first_timestamp = first.frame, first.timestamp
        message.last_frame, message.last_timestamp = completing.frame, completing.timestamp
        frames: list[int] = []
        for piece in pieces:
            if piece.frame not in frames:
                frames.append(piece.frame)
        message.frames = frames

    def next_piece_start(self, position: int) -> Optional[int]:
        index = bisect_right(self.offsets, position)
        return self.offsets[index] if index < len(self.offsets) else None


def _parse_headers(block: bytes) -> list[tuple[str, str]]:
    headers: list[tuple[str, str]] = []
    for line in block.split(b"\r\n"):
        if not line:
            continue
        if line[:1] in (b" ", b"\t") and headers:       # folded continuation line
            name, value = headers[-1]
            headers[-1] = (name, value + " " + line.strip().decode("latin-1"))
            continue
        name, separator, value = line.partition(b":")
        if separator:
            headers.append((name.strip().decode("latin-1"), value.strip().decode("latin-1")))
    return headers


def _read_chunked_body(data: bytes, position: int) -> tuple[int, int, bool]:
    """Walk a chunked body. Returns (end position, body bytes seen, complete?)."""
    body_bytes = 0
    while True:
        line_end = data.find(b"\r\n", position, position + 64)
        if line_end == -1:
            return len(data), body_bytes, False
        size_text = data[position:line_end].split(b";", 1)[0].strip()
        try:
            size = int(size_text, 16)
        except ValueError:
            return position, body_bytes, False            # not valid chunked encoding
        position = line_end + 2
        if size == 0:
            # Optional trailer headers, then an empty line.
            if data.startswith(b"\r\n", position):
                return position + 2, body_bytes, True
            trailer_end = data.find(b"\r\n\r\n", position)
            if trailer_end == -1:
                return len(data), body_bytes, False
            return trailer_end + 4, body_bytes, True
        if position + size + 2 > len(data):
            return len(data), body_bytes + max(0, len(data) - position), False
        body_bytes += size
        position += size + 2                               # chunk data + CRLF


def _parse_direction(direction: DirectionStream, request_methods: Optional[list[str]] = None) -> list[_Parsed]:
    """Parse every HTTP message of one direction, chunk by chunk.

    ``request_methods`` is given when parsing responses: the method of the k-th
    request tells us whether the k-th response may have a body (HEAD never does).
    """
    parsed: list[_Parsed] = []
    final_responses = 0
    for chunk_index, (data, pieces) in enumerate(zip(direction.chunks, direction.chunk_pieces)):
        index = _ChunkIndex(pieces)
        position: Optional[int] = 0
        in_sync = chunk_index == 0 and not direction.starts_mid_stream
        is_last_chunk = chunk_index == len(direction.chunks) - 1
        while position is not None and position < len(data):
            if not _looks_like_http(data, position):
                # Not at a message boundary (mid-stream capture, bytes after a gap,
                # or a non-HTTP protocol). Re-synchronise only at the start of a
                # TCP segment, where a new message would normally begin.
                position = index.next_piece_start(position)
                while position is not None and not _looks_like_http(data, position):
                    position = index.next_piece_start(position)
                in_sync = False
                continue

            line_end = data.find(b"\r\n", position, position + MAX_START_LINE)
            header_end = data.find(b"\r\n\r\n", position)
            start_line = data[position:line_end if line_end != -1 else len(data)]
            request_match = _REQUEST_LINE.match(start_line)
            status_match = _STATUS_LINE.match(start_line)
            malformed_line = line_end != -1 and not request_match and not status_match
            oversized_line = line_end == -1 and header_end != -1
            if malformed_line or oversized_line:
                position = index.next_piece_start(position)      # looked like HTTP but is not
                continue

            message = HttpMessage(is_request=_looks_like_request(data, position),
                                  start_line=start_line.decode("latin-1", "replace"))
            if request_match:
                message.method = request_match.group(1).decode()
                message.uri = request_match.group(2).decode("latin-1")
                message.version = request_match.group(3).decode()
            elif status_match:
                message.version = status_match.group(1).decode()
                message.status_code = int(status_match.group(2))
                message.reason = (status_match.group(3) or b"").decode("latin-1")

            if header_end == -1:                                   # headers never finish
                message.complete = False
                message.warnings.append("The message headers are cut off (the rest was not captured).")
                if line_end != -1:
                    message.headers = _parse_headers(data[line_end + 2:])
                index.describe(message, position, len(data))
                parsed.append(_Parsed(message, chunk_index))
                break

            message.headers = _parse_headers(data[line_end + 2:header_end])
            body_start = header_end + 4
            end = body_start
            transfer_encoding = message.header("Transfer-Encoding").lower()
            content_length_text = message.header("Content-Length")
            has_no_body = False
            if not message.is_request:
                status = message.status_code or 0
                method = ""
                if request_methods is not None and final_responses < len(request_methods):
                    method = request_methods[final_responses]
                has_no_body = status < 200 or status in (204, 304) or method == "HEAD"
                if status >= 200 or status == 101:
                    final_responses += 1

            if has_no_body:
                message.framing = "none"
            elif "chunked" in transfer_encoding:
                message.framing = "chunked"
                end, message.body_length, message.complete = _read_chunked_body(data, body_start)
                if not message.complete:
                    message.warnings.append("The chunked body is incomplete (the final chunk was not captured).")
            elif content_length_text.strip().isdigit():
                message.framing = "content-length"
                message.declared_length = int(content_length_text.strip())
                available = len(data) - body_start
                message.body_length = min(available, message.declared_length)
                end = body_start + message.body_length
                if available < message.declared_length:
                    message.complete = False
                    message.warnings.append(
                        f"The body is incomplete: {message.body_length:,} of "
                        f"{message.declared_length:,} bytes were captured.")
            elif not message.is_request:
                message.framing = "until-close"                    # body runs until the server closes
                end = len(data)
                message.body_length = end - body_start
                if not (is_last_chunk and direction.fin_frame):
                    message.complete = False
                    message.warnings.append(
                        "The response has no Content-Length and the connection close was not captured, "
                        "so the end of the body cannot be confirmed.")

            if not in_sync and chunk_index == 0 and direction.starts_mid_stream and not parsed:
                message.warnings.append("The capture started in the middle of this TCP connection.")
            index.describe(message, position, max(end, position + 1))
            parsed.append(_Parsed(message, chunk_index))
            if not message.complete:
                break                                              # nothing reliable after a cut-off message
            if not message.is_request and message.status_code == 101:
                return parsed                                      # protocol switched (e.g. WebSocket)
            position = end
            in_sync = True
    return parsed


def _first_message_kind(direction: DirectionStream) -> str:
    """'request', 'response' or '' - what kind of HTTP message this direction carries."""
    for data, pieces in zip(direction.chunks, direction.chunk_pieces):
        for piece in pieces:
            if _looks_like_request(data, piece.offset) and b" HTTP/1." in data[piece.offset:piece.offset + MAX_START_LINE]:
                return "request"
            if _looks_like_response(data, piece.offset):
                return "response"
    return ""


def _match_stream(stream: TcpStream, requests: list[_Parsed], responses: list[_Parsed]) -> list[HttpTransaction]:
    """Pair requests and responses of one connection (see module docstring)."""
    transactions: list[HttpTransaction] = []
    pending: deque[_Parsed] = deque(requests)
    informational: list[HttpMessage] = []
    gap_note = (
        f"TCP stream {stream.stream_id} has missing bytes "
        f"(client→server: {stream.client.gap_bytes:,}, server→client: {stream.server.gap_bytes:,}); "
        "a message may have been lost, so this pairing cannot be proven."
    )

    def build(request: Optional[_Parsed], response: Optional[_Parsed]) -> HttpTransaction:
        transaction = HttpTransaction(
            transaction_id="", stream_id=stream.stream_id, index_in_stream=0,
            client_ip=stream.client.src_ip, client_port=stream.client.src_port,
            server_ip=stream.server.src_ip, server_port=stream.server.src_port,
            request=request.message if request else None,
            response=response.message if response else None,
        )
        for parsed_message in (request, response):
            if parsed_message:
                transaction.warnings.extend(parsed_message.message.warnings)
        return transaction

    for response in responses:
        status = response.message.status_code or 0
        after_gap = response.chunk_index > 0
        if after_gap:
            # A response may have been lost in the gap. Requests whose successor was
            # already sent before this response began cannot be answered by it
            # (assuming no pipelining) - report them as unanswered instead of
            # shifting every later pair by one.
            while len(pending) >= 2 and pending[1].message.first_frame < response.message.first_frame:
                skipped = build(pending.popleft(), None)
                skipped.warnings.append("No response found: it was probably lost in a capture gap. " + gap_note)
                transactions.append(skipped)

        head = pending[0] if pending else None
        if head is None or head.message.first_frame > response.message.first_frame:
            orphan = build(None, response)
            orphan.warnings.append(
                "Response without a captured request (the request was sent before the capture started "
                "or was lost), so no response time can be calculated.")
            transactions.append(orphan)
            continue

        if 100 <= status < 200 and status != 101:
            informational.append(response.message)       # e.g. 100 Continue: keep waiting for the real answer
            continue

        pending.popleft()
        transaction = build(head, response)
        transaction.informational, informational = informational, []
        if after_gap or head.chunk_index > 0:
            transaction.match_confidence = "uncertain"
            transaction.warnings.append("Uncertain match. " + gap_note)
        else:
            transaction.match_confidence = "confirmed"
        transactions.append(transaction)

    for request in pending:                               # requests that never got an answer
        transaction = build(request, None)
        reason = "No response was captured for this request"
        if stream.server.gap_bytes:
            reason += " (the server→client direction has missing bytes)"
        elif stream.client.rst_frame or stream.server.rst_frame:
            reason += " (the connection was reset)"
        elif not (stream.client.fin_frame or stream.server.fin_frame):
            reason += " (the capture ended while the connection was still open)"
        transaction.warnings.append(reason + ".")
        transactions.append(transaction)
    return transactions


# --------------------------------------------------------------------------
# TLS / HTTPS metadata
# --------------------------------------------------------------------------
def _tls_handshake_body(data: bytes, expected_type: int) -> Optional[bytes]:
    """Return the body of the first TLS handshake message if it has ``expected_type``."""
    if len(data) < 6 or data[0] != 0x16 or data[1] != 0x03 or data[2] > 0x04:
        return None
    # A handshake message may span several TLS records: join their payloads.
    payload, position = b"", 0
    while position + 5 <= len(data) and data[position] == 0x16:
        record_length = struct.unpack_from("!H", data, position + 3)[0]
        payload += data[position + 5:position + 5 + record_length]
        position += 5 + record_length
        if len(payload) >= 4 and len(payload) >= 4 + int.from_bytes(payload[1:4], "big"):
            break
    if len(payload) < 4 or payload[0] != expected_type:
        return None
    return payload[4:4 + int.from_bytes(payload[1:4], "big")]


def _tls_extensions(body: bytes, position: int) -> dict[int, bytes]:
    extensions: dict[int, bytes] = {}
    if position + 2 > len(body):
        return extensions
    end = min(len(body), position + 2 + struct.unpack_from("!H", body, position)[0])
    position += 2
    while position + 4 <= end:
        extension_type, length = struct.unpack_from("!HH", body, position)
        extensions[extension_type] = body[position + 4:position + 4 + length]
        position += 4 + length
    return extensions


def _parse_client_hello(body: bytes) -> tuple[str, list[str]]:
    """Return (server name, ALPN protocol list) from a ClientHello body."""
    position = 2 + 32                                     # version + random
    position += 1 + body[position]                        # session id
    position += 2 + struct.unpack_from("!H", body, position)[0]   # cipher suites
    position += 1 + body[position]                        # compression methods
    extensions = _tls_extensions(body, position)
    server_name, alpn = "", []
    sni = extensions.get(0x0000, b"")
    if len(sni) >= 5 and sni[2] == 0:
        name_length = struct.unpack_from("!H", sni, 3)[0]
        server_name = sni[5:5 + name_length].decode("ascii", "replace")
    alpn_data = extensions.get(0x0010, b"")
    cursor = 2
    while cursor < len(alpn_data):
        length = alpn_data[cursor]
        alpn.append(alpn_data[cursor + 1:cursor + 1 + length].decode("ascii", "replace"))
        cursor += 1 + length
    return server_name, alpn


def _parse_server_hello_version(body: bytes) -> str:
    version = struct.unpack_from("!H", body, 0)[0]
    position = 2 + 32
    position += 1 + body[position]                        # session id
    position += 2 + 1                                     # cipher suite + compression method
    supported = _tls_extensions(body, position).get(0x002B, b"")
    if len(supported) >= 2:                               # TLS 1.3 announces itself here
        version = struct.unpack_from("!H", supported, 0)[0]
    return TLS_VERSIONS.get(version, f"0x{version:04x}")


def _looks_like_tls(data: bytes) -> bool:
    return len(data) >= 5 and 0x14 <= data[0] <= 0x17 and data[1] == 0x03 and data[2] <= 0x04


def _detect_tls(stream: TcpStream, analysis: CaptureAnalysis) -> Optional[TlsSession]:
    client_data = stream.client.chunks[0] if stream.client.chunks else b""
    server_data = stream.server.chunks[0] if stream.server.chunks else b""
    if not (_looks_like_tls(client_data) or _looks_like_tls(server_data)):
        return None
    # If the first packet we saw came from the server, the roles are swapped.
    if _tls_handshake_body(server_data, 1) is not None and _tls_handshake_body(client_data, 1) is None:
        stream.client, stream.server = stream.server, stream.client
        client_data, server_data = server_data, client_data

    session = TlsSession(
        stream_id=stream.stream_id,
        client_ip=stream.client.src_ip, client_port=stream.client.src_port,
        server_ip=stream.server.src_ip, server_port=stream.server.src_port,
        client_bytes=stream.client.payload_bytes, server_bytes=stream.server.payload_bytes,
    )
    try:
        client_hello = _tls_handshake_body(client_data, 1)
        if client_hello is not None:
            first_piece = stream.client.chunk_pieces[0][0]
            session.client_hello_frame, session.client_hello_timestamp = first_piece.frame, first_piece.timestamp
            session.server_name, session.alpn = _parse_client_hello(client_hello)
    except (IndexError, struct.error):
        pass                                              # truncated ClientHello: keep what we have
    try:
        server_hello = _tls_handshake_body(server_data, 2)
        if server_hello is not None:
            first_piece = stream.server.chunk_pieces[0][0]
            session.server_hello_frame, session.server_hello_timestamp = first_piece.frame, first_piece.timestamp
            session.tls_version = _parse_server_hello_version(server_hello)
    except (IndexError, struct.error):
        pass

    stream.app_protocol = "TLS"
    for frame in stream.frames:
        packet = analysis.packets[frame - 1]
        if packet.payload_length == 0:
            continue
        packet.protocol, packet.identification = "TLS", ID_CONTENT
        if frame == session.client_hello_frame:
            detail = "Client Hello" + (f" (SNI={session.server_name})" if session.server_name else "")
        elif frame == session.server_hello_frame:
            detail = "Server Hello" + (f" ({session.tls_version})" if session.tls_version else "")
        else:
            detail = "Encrypted TLS data"
        prefix = f"[TCP {packet.tcp_analysis}] " if packet.tcp_analysis else ""
        packet.info = f"{prefix}{detail}, Len={packet.payload_length}"
    return session


# --------------------------------------------------------------------------
# Entry point
# --------------------------------------------------------------------------
def analyze_http(analysis: CaptureAnalysis) -> None:
    """Fill ``analysis.transactions`` and ``analysis.tls_sessions``."""
    transactions: list[HttpTransaction] = []
    analysis.tls_sessions = []

    for stream in analysis.streams:
        client_kind = _first_message_kind(stream.client)
        server_kind = _first_message_kind(stream.server)
        if not client_kind and not server_kind:
            session = _detect_tls(stream, analysis)
            if session:
                analysis.tls_sessions.append(session)
            continue

        # Roles come from the content: whoever sends requests is the HTTP client.
        if server_kind == "request" or (client_kind == "response" and server_kind != "response"):
            stream.client, stream.server = stream.server, stream.client

        requests = [item for item in _parse_direction(stream.client) if item.message.is_request]
        methods = [item.message.method for item in requests]
        responses = [item for item in _parse_direction(stream.server, methods) if not item.message.is_request]
        if not requests and not responses:
            continue
        stream.app_protocol = "HTTP"

        stream_transactions = _match_stream(stream, requests, responses)
        for position, transaction in enumerate(stream_transactions, start=1):
            transaction.index_in_stream = position
            _label_packets(analysis, transaction)
        transactions.extend(stream_transactions)

    # Number transactions in capture order so identifiers are stable and readable.
    def sort_key(transaction: HttpTransaction) -> int:
        message = transaction.request or transaction.response
        return message.first_frame if message else 0

    transactions.sort(key=sort_key)
    for number, transaction in enumerate(transactions, start=1):
        transaction.transaction_id = f"T{number:04d}"
    analysis.transactions = transactions


def _label_packets(analysis: CaptureAnalysis, transaction: HttpTransaction) -> None:
    """Mark the frames of HTTP messages in the packet table (as Wireshark does)."""
    messages = [transaction.request, transaction.response, *transaction.informational]
    for message in messages:
        if message is None:
            continue
        # A complete message is shown on the frame that completes it; a cut-off
        # message is shown on the frame where it starts.
        label_frame = message.last_frame if message.complete else message.first_frame
        for frame in message.frames:
            packet = analysis.packets[frame - 1]
            prefix = f"[TCP {packet.tcp_analysis}] " if packet.tcp_analysis else ""
            if frame == label_frame:
                if packet.protocol == "HTTP":             # several messages complete in one frame
                    packet.info += " | " + message.start_line
                else:
                    packet.protocol, packet.identification = "HTTP", ID_CONTENT
                    packet.info = prefix + message.start_line
            elif packet.protocol != "HTTP" and "reassembled" not in packet.info:
                packet.info += " [TCP segment of a reassembled HTTP message]"
