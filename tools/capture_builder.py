"""Build synthetic packet captures with exactly known contents.

Used by the automated tests (so every expected answer is known in advance)
and by ``generate_sample_capture.py``. Packets are crafted with Scapy and
written as real PCAP / PCAPNG files, then analysed by the normal engine.
"""

from __future__ import annotations

import os
import tempfile
from typing import Optional

from scapy.layers.inet import ICMP, IP, TCP, UDP
from scapy.layers.dns import DNS, DNSQR, DNSRR
from scapy.layers.l2 import ARP, Ether
from scapy.packet import Raw
from scapy.utils import wrpcap, wrpcapng

CLIENT_MAC = "02:00:00:00:00:01"
SERVER_MAC = "02:00:00:00:00:02"


class CaptureBuilder:
    """Collects packets, giving each one a timestamp and a frame number."""

    def __init__(self, start_time: float = 1_700_000_000.0) -> None:
        self.packets: list = []
        self.time = start_time

    def add(self, packet, delay: float = 0.001) -> int:
        """Append a packet ``delay`` seconds after the previous one. Returns its frame number."""
        self.time = round(self.time + delay, 6)
        packet.time = self.time
        self.packets.append(packet)
        return len(self.packets)

    def to_bytes(self, file_format: str = "pcap") -> bytes:
        handle, path = tempfile.mkstemp(suffix="." + file_format)
        os.close(handle)
        try:
            self.write(path, file_format)
            with open(path, "rb") as capture_file:
                return capture_file.read()
        finally:
            os.remove(path)

    def write(self, path: str, file_format: str = "pcap") -> None:
        if file_format == "pcapng":
            wrpcapng(path, self.packets)
        else:
            wrpcap(path, self.packets)

    # ---- non-TCP helpers -------------------------------------------------
    def dns_lookup(self, client_ip: str, resolver_ip: str, name: str, answer_ip: Optional[str],
                   client_port: int = 53000, delay: float = 0.001) -> tuple[int, int]:
        query = (Ether(src=CLIENT_MAC, dst=SERVER_MAC) / IP(src=client_ip, dst=resolver_ip)
                 / UDP(sport=client_port, dport=53) / DNS(id=0x1A2B, rd=1, qd=DNSQR(qname=name)))
        if answer_ip:
            reply_dns = DNS(id=0x1A2B, qr=1, rd=1, ra=1, qd=DNSQR(qname=name),
                            an=DNSRR(rrname=name, ttl=60, rdata=answer_ip))
        else:
            reply_dns = DNS(id=0x1A2B, qr=1, rd=1, ra=1, rcode=3, qd=DNSQR(qname=name))
        reply = (Ether(src=SERVER_MAC, dst=CLIENT_MAC) / IP(src=resolver_ip, dst=client_ip)
                 / UDP(sport=53, dport=client_port) / reply_dns)
        return self.add(query, delay), self.add(reply, 0.004)

    def arp_request(self, sender_ip: str, target_ip: str) -> int:
        return self.add(Ether(src=CLIENT_MAC, dst="ff:ff:ff:ff:ff:ff") / ARP(op=1, psrc=sender_ip, pdst=target_ip))

    def ping(self, source_ip: str, destination_ip: str) -> tuple[int, int]:
        request = Ether(src=CLIENT_MAC, dst=SERVER_MAC) / IP(src=source_ip, dst=destination_ip) / ICMP(type=8) / Raw(b"ping")
        reply = Ether(src=SERVER_MAC, dst=CLIENT_MAC) / IP(src=destination_ip, dst=source_ip) / ICMP(type=0) / Raw(b"ping")
        return self.add(request), self.add(reply)


class TcpConversation:
    """Generates the packets of one TCP connection with correct seq/ack numbers."""

    def __init__(self, capture: CaptureBuilder, client_ip: str, server_ip: str, client_port: int,
                 server_port: int = 80, client_isn: int = 1000, server_isn: int = 5000) -> None:
        self.capture = capture
        self.client_ip, self.server_ip = client_ip, server_ip
        self.client_port, self.server_port = client_port, server_port
        self.client_seq, self.server_seq = client_isn, server_isn

    def _packet(self, from_client: bool, flags: str, payload: bytes = b"", sequence: Optional[int] = None):
        if from_client:
            ethernet = Ether(src=CLIENT_MAC, dst=SERVER_MAC)
            ip = IP(src=self.client_ip, dst=self.server_ip)
            tcp = TCP(sport=self.client_port, dport=self.server_port, flags=flags,
                      seq=(self.client_seq if sequence is None else sequence) % 2**32, ack=self.server_seq % 2**32)
        else:
            ethernet = Ether(src=SERVER_MAC, dst=CLIENT_MAC)
            ip = IP(src=self.server_ip, dst=self.client_ip)
            tcp = TCP(sport=self.server_port, dport=self.client_port, flags=flags,
                      seq=(self.server_seq if sequence is None else sequence) % 2**32, ack=self.client_seq % 2**32)
        packet = ethernet / ip / tcp
        return packet / Raw(payload) if payload else packet

    def handshake(self, delay: float = 0.001) -> tuple[int, int, int]:
        syn = self.capture.add(self._packet(True, "S"), delay)
        self.client_seq += 1
        syn_ack = self.capture.add(self._packet(False, "SA"), 0.001)
        self.server_seq += 1
        ack = self.capture.add(self._packet(True, "A"), 0.001)
        return syn, syn_ack, ack

    def send(self, from_client: bool, payload: bytes, delay: float = 0.001, flags: str = "PA") -> int:
        """Send new data and advance the sender's sequence number."""
        frame = self.capture.add(self._packet(from_client, flags, payload), delay)
        if from_client:
            self.client_seq += len(payload)
        else:
            self.server_seq += len(payload)
        return frame

    def client(self, payload: bytes, delay: float = 0.001) -> int:
        return self.send(True, payload, delay)

    def server(self, payload: bytes, delay: float = 0.001) -> int:
        return self.send(False, payload, delay)

    def resend(self, from_client: bool, payload: bytes, sequence: int, delay: float = 0.001) -> int:
        """Emit data at an explicit sequence number without advancing (retransmission / reordering)."""
        return self.capture.add(self._packet(from_client, "PA", payload, sequence), delay)

    def lose(self, from_client: bool, byte_count: int) -> None:
        """Pretend ``byte_count`` bytes were sent but never captured (creates a gap)."""
        if from_client:
            self.client_seq += byte_count
        else:
            self.server_seq += byte_count

    def ack(self, from_client: bool, delay: float = 0.0005) -> int:
        return self.capture.add(self._packet(from_client, "A"), delay)

    def close(self, delay: float = 0.001) -> tuple[int, int, int]:
        fin = self.capture.add(self._packet(True, "FA"), delay)
        self.client_seq += 1
        fin_ack = self.capture.add(self._packet(False, "FA"), 0.001)
        self.server_seq += 1
        last_ack = self.capture.add(self._packet(True, "A"), 0.001)
        return fin, fin_ack, last_ack

    def reset(self, from_client: bool = False, delay: float = 0.001) -> int:
        return self.capture.add(self._packet(from_client, "R"), delay)


def http_request(method: str, uri: str, host: str, body: bytes = b"", extra_headers: str = "") -> bytes:
    head = f"{method} {uri} HTTP/1.1\r\nHost: {host}\r\nUser-Agent: nta-test/1.0\r\n{extra_headers}"
    if body:
        head += f"Content-Length: {len(body)}\r\n"
    return head.encode() + b"\r\n" + body


def http_response(status: int, reason: str, body: bytes = b"", content_type: str = "text/html",
                  extra_headers: str = "", chunked: bool = False, with_length: bool = True) -> bytes:
    head = f"HTTP/1.1 {status} {reason}\r\nServer: nta-test\r\n{extra_headers}"
    if body or chunked:
        head += f"Content-Type: {content_type}\r\n"
    if chunked:
        head += "Transfer-Encoding: chunked\r\n"
        middle = len(body) // 2
        parts = [part for part in (body[:middle], body[middle:]) if part]
        encoded = b"".join(f"{len(part):x}\r\n".encode() + part + b"\r\n" for part in parts) + b"0\r\n\r\n"
        return head.encode() + b"\r\n" + encoded
    if with_length:
        head += f"Content-Length: {len(body)}\r\n"
    return head.encode() + b"\r\n" + body


def tls_client_hello(server_name: str) -> bytes:
    """A minimal but well-formed TLS 1.2-style ClientHello record with SNI and ALPN."""
    name = server_name.encode()
    sni = b"\x00\x00" + (len(name) + 5).to_bytes(2, "big") + (len(name) + 3).to_bytes(2, "big") + b"\x00" \
        + len(name).to_bytes(2, "big") + name
    alpn_list = b"\x02h2\x08http/1.1"
    alpn = b"\x00\x10" + (len(alpn_list) + 2).to_bytes(2, "big") + len(alpn_list).to_bytes(2, "big") + alpn_list
    extensions = sni + alpn
    body = (b"\x03\x03" + bytes(range(32)) + b"\x00" + b"\x00\x04\x13\x01\xc0\x2f" + b"\x01\x00"
            + len(extensions).to_bytes(2, "big") + extensions)
    handshake = b"\x01" + len(body).to_bytes(3, "big") + body
    return b"\x16\x03\x01" + len(handshake).to_bytes(2, "big") + handshake


def tls_server_hello(tls13: bool = True) -> bytes:
    extensions = b"\x00\x2b\x00\x02\x03\x04" if tls13 else b""
    body = (b"\x03\x03" + bytes(range(32, 64)) + b"\x00" + b"\x13\x01" + b"\x00"
            + len(extensions).to_bytes(2, "big") + extensions)
    handshake = b"\x02" + len(body).to_bytes(3, "big") + body
    return b"\x16\x03\x03" + len(handshake).to_bytes(2, "big") + handshake


def tls_application_data(length: int = 120) -> bytes:
    return b"\x17\x03\x03" + length.to_bytes(2, "big") + bytes((i * 7) % 256 for i in range(length))
