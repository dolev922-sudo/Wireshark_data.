"""Reading PCAP / PCAPNG files and decoding every frame.

How it works (student-friendly summary)
---------------------------------------
1. The first four bytes of the file (the "magic number") tell us whether it is
   a classic PCAP or a PCAPNG file. Anything else is rejected with a clear
   error - we never guess.
2. Scapy's ``RawPcapReader`` / ``RawPcapNgReader`` walks the file and gives us
   the raw bytes and the timestamp of each frame, in file order. The position
   in the file is the *frame number* (1-based, exactly like Wireshark).
3. Each frame is decoded layer by layer with small, explicit functions:
   link layer -> IPv4/IPv6/ARP -> TCP/UDP/ICMP. Every length is checked, so a
   truncated or malformed frame produces a ``decode_error`` note instead of a
   crash or an invented value.
4. The raw bytes are kept, so the dashboard can show a full Scapy dissection
   and a hex dump of any single frame on demand.

Decoding the common headers ourselves (instead of building a full Scapy packet
object for every frame) keeps large captures fast and gives exact control over
truncated data.
"""

from __future__ import annotations

import hashlib
import io
import ipaddress
import logging
import struct
from typing import Callable, Optional

from scapy.utils import RawPcapNgReader, RawPcapReader

from .models import (
    ID_CONTENT,
    ID_HEADER,
    ID_PORT,
    ID_TRANSPORT,
    ID_UNKNOWN,
    CaptureAnalysis,
    PacketRecord,
)

# Scapy prints warnings for damaged files; we report those problems ourselves.
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

PCAP_MAGICS = {
    b"\xa1\xb2\xc3\xd4", b"\xd4\xc3\xb2\xa1",   # microsecond timestamps
    b"\xa1\xb2\x3c\x4d", b"\x4d\x3c\xb2\xa1",   # nanosecond timestamps
}
PCAPNG_MAGIC = b"\x0a\x0d\x0d\x0a"

# Link-layer header types (https://www.tcpdump.org/linktypes.html)
LINKTYPE_NULL = 0
LINKTYPE_ETHERNET = 1
LINKTYPE_RAW = 101
LINKTYPE_LINUX_SLL = 113
LINKTYPE_IPV4 = 228
LINKTYPE_IPV6 = 229
LINKTYPE_LINUX_SLL2 = 276
SUPPORTED_LINKTYPES = {
    LINKTYPE_NULL, LINKTYPE_ETHERNET, LINKTYPE_RAW, LINKTYPE_LINUX_SLL,
    LINKTYPE_IPV4, LINKTYPE_IPV6, LINKTYPE_LINUX_SLL2,
}

ETHERTYPE_IPV4 = 0x0800
ETHERTYPE_ARP = 0x0806
ETHERTYPE_VLAN = 0x8100
ETHERTYPE_QINQ = 0x88A8
ETHERTYPE_IPV6 = 0x86DD
ETHERTYPE_NAMES = {0x88CC: "LLDP", 0x8035: "RARP", 0x888E: "EAPOL", 0x8863: "PPPoE", 0x8864: "PPPoE"}

IP_PROTO_ICMP, IP_PROTO_IGMP, IP_PROTO_TCP, IP_PROTO_UDP, IP_PROTO_ICMPV6 = 1, 2, 6, 17, 58
IP_PROTO_NAMES = {2: "IGMP", 47: "GRE", 50: "ESP", 51: "AH", 89: "OSPF", 132: "SCTP"}
IPV6_EXTENSION_HEADERS = {0, 43, 60}    # hop-by-hop, routing, destination options
IPV6_FRAGMENT_HEADER = 44

TCP_FLAG_NAMES = [(0x02, "SYN"), (0x01, "FIN"), (0x04, "RST"), (0x08, "PSH"), (0x10, "ACK"), (0x20, "URG")]
FLAG_FIN, FLAG_SYN, FLAG_RST, FLAG_PSH, FLAG_ACK = 0x01, 0x02, 0x04, 0x08, 0x10

# UDP services recognised by port only (label is marked as a *guess*).
UDP_PORT_GUESSES = {123: "NTP", 137: "NBNS", 138: "NetBIOS", 161: "SNMP", 443: "QUIC", 514: "Syslog", 5355: "LLMNR"}
DNS_PORTS = {53: "DNS", 5353: "mDNS", 5355: "LLMNR"}
DNS_TYPES = {1: "A", 2: "NS", 5: "CNAME", 6: "SOA", 12: "PTR", 15: "MX", 16: "TXT", 28: "AAAA", 33: "SRV", 65: "HTTPS", 255: "ANY"}
ICMP_TYPES = {0: "Echo reply", 3: "Destination unreachable", 5: "Redirect", 8: "Echo request", 11: "Time exceeded"}
ICMPV6_TYPES = {
    1: "Destination unreachable", 3: "Time exceeded", 128: "Echo request", 129: "Echo reply",
    133: "Router solicitation", 134: "Router advertisement",
    135: "Neighbor solicitation", 136: "Neighbor advertisement",
}


class CaptureError(Exception):
    """The uploaded file cannot be analysed (empty, not a capture, ...)."""


def detect_format(data: bytes) -> str:
    """Return "pcap" or "pcapng", or raise CaptureError for anything else."""
    if len(data) == 0:
        raise CaptureError("The file is empty (0 bytes).")
    magic = data[:4]
    if magic in PCAP_MAGICS:
        if len(data) < 24:
            raise CaptureError("The PCAP file is truncated: its 24-byte global header is incomplete.")
        return "pcap"
    if magic == PCAPNG_MAGIC:
        return "pcapng"
    raise CaptureError(
        "Unsupported file: this is not a PCAP or PCAPNG capture "
        "(the file does not start with a known capture magic number)."
    )


def tcp_flags_text(flags: int) -> str:
    return ", ".join(name for bit, name in TCP_FLAG_NAMES if flags & bit)


def _mac(raw: bytes) -> str:
    return ":".join(f"{byte:02x}" for byte in raw)


def _ipv6(raw: bytes) -> str:
    return str(ipaddress.IPv6Address(raw))


def _ipv4(raw: bytes) -> str:
    return "%d.%d.%d.%d" % tuple(raw)


# --------------------------------------------------------------------------
# Frame decoding
# --------------------------------------------------------------------------
def decode_frame(frame: int, timestamp: float, wire_length: int, link_type: int, data: bytes) -> PacketRecord:
    """Decode one frame into a PacketRecord. Never raises on bad input."""
    record = PacketRecord(
        frame=frame, timestamp=timestamp, captured_length=len(data),
        wire_length=max(wire_length, len(data)), link_type=link_type,
    )
    try:
        _decode_link_layer(record, data)
    except (struct.error, IndexError, ValueError) as error:   # defensive: malformed bytes
        record.decode_error = record.decode_error or f"malformed frame ({error})"
    if record.decode_error and record.protocol == "Unknown":
        record.info = record.decode_error
    return record


def _decode_link_layer(record: PacketRecord, data: bytes) -> None:
    link_type = record.link_type
    if link_type == LINKTYPE_ETHERNET:
        if len(data) < 14:
            record.decode_error = "truncated Ethernet header"
            return
        record.dst_mac, record.src_mac = _mac(data[0:6]), _mac(data[6:12])
        ethertype = struct.unpack_from("!H", data, 12)[0]
        offset = 14
        while ethertype in (ETHERTYPE_VLAN, ETHERTYPE_QINQ):      # skip VLAN tags
            if len(data) < offset + 4:
                record.decode_error = "truncated VLAN tag"
                return
            ethertype = struct.unpack_from("!H", data, offset + 2)[0]
            offset += 4
        _decode_network_layer(record, data, offset, ethertype)
    elif link_type == LINKTYPE_LINUX_SLL:
        if len(data) < 16:
            record.decode_error = "truncated Linux cooked header"
            return
        _decode_network_layer(record, data, 16, struct.unpack_from("!H", data, 14)[0])
    elif link_type == LINKTYPE_LINUX_SLL2:
        if len(data) < 20:
            record.decode_error = "truncated Linux cooked v2 header"
            return
        _decode_network_layer(record, data, 20, struct.unpack_from("!H", data, 0)[0])
    elif link_type == LINKTYPE_NULL:
        if len(data) < 4:
            record.decode_error = "truncated loopback header"
            return
        family = struct.unpack_from("<I", data, 0)[0]
        if family > 0xFFFF:                                        # written by a big-endian host
            family = struct.unpack_from(">I", data, 0)[0]
        ethertype = ETHERTYPE_IPV4 if family == 2 else ETHERTYPE_IPV6 if family in (10, 24, 28, 30) else None
        _decode_network_layer(record, data, 4, ethertype)
    elif link_type in (LINKTYPE_RAW, LINKTYPE_IPV4, LINKTYPE_IPV6):
        if not data:
            record.decode_error = "empty frame"
            return
        version = data[0] >> 4
        ethertype = ETHERTYPE_IPV4 if version == 4 else ETHERTYPE_IPV6 if version == 6 else None
        _decode_network_layer(record, data, 0, ethertype)
    else:
        record.protocol = "Unsupported link type"
        record.identification = ID_UNKNOWN
        record.info = f"Link-layer type {link_type} is not supported by this analyzer"


def _decode_network_layer(record: PacketRecord, data: bytes, offset: int, ethertype: Optional[int]) -> None:
    record.ethertype = ethertype
    if ethertype == ETHERTYPE_IPV4:
        _decode_ipv4(record, data, offset)
    elif ethertype == ETHERTYPE_IPV6:
        _decode_ipv6(record, data, offset)
    elif ethertype == ETHERTYPE_ARP:
        _decode_arp(record, data, offset)
    elif ethertype is not None and ethertype in ETHERTYPE_NAMES:
        record.protocol, record.identification = ETHERTYPE_NAMES[ethertype], ID_HEADER
        record.info = f"{record.protocol} frame"
    elif ethertype is not None and ethertype < 0x0600:
        record.protocol, record.identification = "LLC", ID_HEADER       # IEEE 802.3 length field (e.g. STP)
        record.info = "IEEE 802.3 / LLC frame"
    else:
        record.protocol, record.identification = "Other", ID_UNKNOWN
        record.info = "Unrecognised network protocol" + (f" (EtherType 0x{ethertype:04x})" if ethertype is not None else "")


def _decode_arp(record: PacketRecord, data: bytes, offset: int) -> None:
    record.protocol, record.transport, record.identification = "ARP", "ARP", ID_HEADER
    if len(data) < offset + 28:
        record.decode_error = "truncated ARP packet"
        return
    operation = struct.unpack_from("!H", data, offset + 6)[0]
    sender_ip, target_ip = _ipv4(data[offset + 14:offset + 18]), _ipv4(data[offset + 24:offset + 28])
    record.src_ip, record.dst_ip = sender_ip, target_ip
    if operation == 1:
        record.info = f"Who has {target_ip}? Tell {sender_ip}"
    elif operation == 2:
        record.info = f"{sender_ip} is at {_mac(data[offset + 8:offset + 14])}"
    else:
        record.info = f"ARP operation {operation}"


def _decode_ipv4(record: PacketRecord, data: bytes, offset: int) -> None:
    record.ip_version = 4
    record.protocol, record.identification = "IPv4", ID_HEADER
    if len(data) < offset + 20:
        record.decode_error = "truncated IPv4 header"
        return
    header_length = (data[offset] & 0x0F) * 4
    if header_length < 20 or len(data) < offset + header_length:
        record.decode_error = "invalid IPv4 header length"
        return
    total_length = struct.unpack_from("!H", data, offset + 2)[0]
    fragment_field = struct.unpack_from("!H", data, offset + 6)[0]
    record.ttl = data[offset + 8]
    record.ip_protocol = data[offset + 9]
    record.src_ip, record.dst_ip = _ipv4(data[offset + 12:offset + 16]), _ipv4(data[offset + 16:offset + 20])

    # total_length == 0 happens with TCP segmentation offload; then trust the capture.
    ip_end = offset + total_length if total_length >= header_length else len(data)
    ip_end = min(ip_end, len(data))        # anything after ip_end is Ethernet padding
    fragment_offset = fragment_field & 0x1FFF
    more_fragments = bool(fragment_field & 0x2000)
    if fragment_offset or more_fragments:
        record.info = f"Fragmented IP packet (offset {fragment_offset * 8})"
        if fragment_offset:                 # no transport header in later fragments
            record.protocol = "IPv4 fragment"
            return
    _decode_transport(record, data, offset + header_length, ip_end)


def _decode_ipv6(record: PacketRecord, data: bytes, offset: int) -> None:
    record.ip_version = 6
    record.protocol, record.identification = "IPv6", ID_HEADER
    if len(data) < offset + 40:
        record.decode_error = "truncated IPv6 header"
        return
    payload_length = struct.unpack_from("!H", data, offset + 4)[0]
    next_header = data[offset + 6]
    record.ttl = data[offset + 7]
    record.src_ip, record.dst_ip = _ipv6(data[offset + 8:offset + 24]), _ipv6(data[offset + 24:offset + 40])
    position = offset + 40
    ip_end = min(position + payload_length, len(data)) if payload_length else len(data)

    while next_header in IPV6_EXTENSION_HEADERS or next_header == IPV6_FRAGMENT_HEADER:
        if position + 8 > ip_end:
            record.decode_error = "truncated IPv6 extension header"
            return
        if next_header == IPV6_FRAGMENT_HEADER:
            fragment_offset = struct.unpack_from("!H", data, position + 2)[0] >> 3
            next_header, position = data[position], position + 8
            if fragment_offset:
                record.ip_protocol = next_header
                record.protocol, record.info = "IPv6 fragment", "Fragmented IPv6 packet"
                return
        else:
            extension_length = (data[position + 1] + 1) * 8
            next_header, position = data[position], position + extension_length
    record.ip_protocol = next_header
    _decode_transport(record, data, position, ip_end)


def _decode_transport(record: PacketRecord, data: bytes, offset: int, end: int) -> None:
    protocol = record.ip_protocol
    if protocol == IP_PROTO_TCP:
        _decode_tcp(record, data, offset, end)
    elif protocol == IP_PROTO_UDP:
        _decode_udp(record, data, offset, end)
    elif protocol == IP_PROTO_ICMP:
        record.protocol, record.transport, record.identification = "ICMP", "ICMP", ID_HEADER
        if end >= offset + 2:
            record.info = ICMP_TYPES.get(data[offset], f"Type {data[offset]}") + f" (code {data[offset + 1]})"
    elif protocol == IP_PROTO_ICMPV6:
        record.protocol, record.transport, record.identification = "ICMPv6", "ICMPv6", ID_HEADER
        if end >= offset + 2:
            record.info = ICMPV6_TYPES.get(data[offset], f"Type {data[offset]}")
    elif protocol in IP_PROTO_NAMES:
        record.protocol, record.identification = IP_PROTO_NAMES[protocol], ID_HEADER
        record.info = f"{record.protocol} packet"
    else:
        record.protocol, record.identification = "Other IP", ID_UNKNOWN
        record.info = f"Unrecognised IP protocol number {protocol}"


def _decode_tcp(record: PacketRecord, data: bytes, offset: int, end: int) -> None:
    record.protocol, record.transport, record.identification = "TCP", "TCP", ID_TRANSPORT
    if end < offset + 20:
        record.decode_error = "truncated TCP header"
        return
    src_port, dst_port, sequence, acknowledgment, offset_byte, flags, window = struct.unpack_from(
        "!HHIIBBH", data, offset)
    header_length = (offset_byte >> 4) * 4
    if header_length < 20 or end < offset + header_length:
        record.decode_error = "invalid TCP header length"
        header_length = max(20, min(header_length, end - offset))
    record.src_port, record.dst_port = src_port, dst_port
    record.tcp_seq, record.tcp_ack, record.tcp_flags, record.tcp_window = sequence, acknowledgment, flags, window
    record.payload_offset = offset + header_length
    record.payload_length = max(0, end - record.payload_offset)
    record.info = (
        f"{src_port} → {dst_port} [{tcp_flags_text(flags)}] "
        f"Seq={sequence} Ack={acknowledgment} Win={window} Len={record.payload_length}"
    )


def _decode_udp(record: PacketRecord, data: bytes, offset: int, end: int) -> None:
    record.protocol, record.transport, record.identification = "UDP", "UDP", ID_TRANSPORT
    if end < offset + 8:
        record.decode_error = "truncated UDP header"
        return
    src_port, dst_port, udp_length = struct.unpack_from("!HHH", data, offset)
    record.src_port, record.dst_port = src_port, dst_port
    record.payload_offset = offset + 8
    payload_end = min(end, offset + udp_length) if udp_length >= 8 else end
    record.payload_length = max(0, payload_end - record.payload_offset)
    payload = data[record.payload_offset:payload_end]
    record.info = f"{src_port} → {dst_port} Len={record.payload_length}"
    _classify_udp(record, payload)


def _classify_udp(record: PacketRecord, payload: bytes) -> None:
    """Label a UDP datagram. Content checks win over port-number guesses."""
    ports = (record.src_port, record.dst_port)
    for port, name in DNS_PORTS.items():
        if port in ports:
            summary = _dns_summary(payload)
            if summary:
                record.protocol, record.identification, record.info = name, ID_CONTENT, summary
                return
    if (67 in ports or 68 in ports) and len(payload) >= 240 and payload[236:240] == b"\x63\x82\x53\x63":
        record.protocol, record.identification = "DHCP", ID_CONTENT
        record.info = "DHCP " + ("request (client → server)" if payload[0] == 1 else "reply (server → client)")
        return
    if 1900 in ports and payload.startswith((b"M-SEARCH ", b"NOTIFY ", b"HTTP/1.1 ")):
        record.protocol, record.identification = "SSDP", ID_CONTENT
        record.info = payload.split(b"\r\n", 1)[0].decode("latin-1", "replace")[:80]
        return
    for port in ports:
        if port in UDP_PORT_GUESSES:
            record.protocol, record.identification = UDP_PORT_GUESSES[port], ID_PORT
            record.info += f" (labelled {record.protocol} from port {port} only)"
            return


def _dns_summary(payload: bytes) -> str:
    """Return a short description of a DNS message, or '' if it does not parse."""
    if len(payload) < 12:
        return ""
    transaction_id, flags, questions, answers = struct.unpack_from("!HHHH", payload, 0)
    if questions > 16:
        return ""
    is_response = bool(flags & 0x8000)
    name, query_type = "", None
    if questions:
        labels, position = [], 12
        while True:
            if position >= len(payload):
                return ""
            length = payload[position]
            if length == 0:
                position += 1
                break
            if length & 0xC0:               # compression pointer is not valid in the first question
                return ""
            labels.append(payload[position + 1:position + 1 + length].decode("latin-1", "replace"))
            position += 1 + length
        if position + 4 > len(payload):
            return ""
        query_type = struct.unpack_from("!H", payload, position)[0]
        name = ".".join(labels) or "<root>"
    type_name = DNS_TYPES.get(query_type, f"type {query_type}") if query_type is not None else ""
    if is_response:
        rcode = flags & 0x000F
        outcome = f"{answers} answer(s)" if rcode == 0 else {3: "No such name"}.get(rcode, f"error code {rcode}")
        return f"Query response 0x{transaction_id:04x} {type_name} {name} - {outcome}".replace("  ", " ")
    return f"Query 0x{transaction_id:04x} {type_name} {name}".replace("  ", " ")


# --------------------------------------------------------------------------
# File reading
# --------------------------------------------------------------------------
def _pcapng_is_truncated(data: bytes) -> bool:
    """Walk the PCAPNG block chain and report whether the file ends mid-block."""
    position, endian = 0, "<"
    while position + 12 <= len(data):
        if data[position:position + 4] == PCAPNG_MAGIC:           # section header: read its byte order
            endian = "<" if data[position + 8:position + 12] == b"\x4d\x3c\x2b\x1a" else ">"
        block_length = struct.unpack_from(endian + "I", data, position + 4)[0]
        if block_length < 12 or position + block_length > len(data):
            return True
        position += block_length
    return position != len(data)


def read_capture(
    data: bytes,
    file_name: str = "capture",
    max_packets: int = 500_000,
    progress: Optional[Callable[[float], None]] = None,
) -> CaptureAnalysis:
    """Read every frame of a PCAP/PCAPNG file held in memory.

    Raises CaptureError when the file is not a capture at all. Problems inside
    an otherwise valid capture (truncation, damaged blocks) are reported in
    ``analysis.warnings`` and the frames read so far are kept.
    """
    file_format = detect_format(data)
    analysis = CaptureAnalysis(
        file_name=file_name, file_size=len(data), file_format=file_format,
        sha256=hashlib.sha256(data).hexdigest(),
    )
    stream = io.BytesIO(data)
    try:
        reader = RawPcapNgReader(stream) if file_format == "pcapng" else RawPcapReader(stream)
    except Exception as error:   # scapy raises several exception types for damaged headers
        raise CaptureError(f"The {file_format.upper()} file header could not be read: {error}") from error

    is_nanosecond = bool(getattr(reader, "nano", False))
    default_link_type = getattr(reader, "linktype", LINKTYPE_ETHERNET)
    unsupported_link_types: set[int] = set()
    frame = 0
    while True:
        try:
            raw, metadata = reader._read_packet()   # raw bytes + per-frame metadata
        except EOFError:
            break
        except Exception as error:   # damaged block in the middle of the file
            analysis.warnings.append(
                f"The capture is damaged after frame {frame}: reading stopped there ({type(error).__name__}).")
            break

        if file_format == "pcap":
            divisor = 1_000_000_000 if is_nanosecond else 1_000_000
            timestamp = metadata.sec + metadata.usec / divisor
            link_type, wire_length = default_link_type, metadata.wirelen
            if len(raw) < min(metadata.caplen, 0xFFFF):
                analysis.warnings.append(
                    f"The capture file ends in the middle of frame {frame + 1}: that incomplete frame was ignored.")
                break
        else:
            ticks = (metadata.tshigh << 32) | metadata.tslow
            timestamp = ticks / (metadata.tsresol or 1_000_000)
            link_type, wire_length = metadata.linktype, metadata.wirelen

        frame += 1
        record = decode_frame(frame, timestamp, wire_length, link_type, raw)
        if link_type not in SUPPORTED_LINKTYPES:
            unsupported_link_types.add(link_type)
        analysis.packets.append(record)
        analysis.raw_frames.append(raw)

        if progress and frame % 5000 == 0:
            progress(min(0.99, stream.tell() / max(1, len(data))))
        if frame >= max_packets:
            analysis.warnings.append(
                f"Only the first {max_packets:,} frames were analysed (MAX_PACKETS safety limit).")
            break

    if file_format == "pcapng" and frame < max_packets and not analysis.warnings and _pcapng_is_truncated(data):
        analysis.warnings.append("The PCAPNG file is truncated: its last block is incomplete and was ignored.")
    if unsupported_link_types:
        analysis.warnings.append(
            "Unsupported link-layer type(s) " + ", ".join(str(t) for t in sorted(unsupported_link_types))
            + ": those frames are counted but not decoded.")
    if frame == 0:
        analysis.warnings.append("The capture file is valid but contains no packets.")
    truncated = sum(1 for p in analysis.packets if p.captured_length < p.wire_length)
    if truncated:
        analysis.warnings.append(
            f"{truncated:,} frame(s) were captured with a snap length shorter than the packet: "
            "their payload is incomplete, so stream reassembly may show gaps.")
    return analysis
