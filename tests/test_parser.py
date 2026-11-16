"""PCAP / PCAPNG reading, invalid input handling and per-packet decoding."""

import struct

import pytest
from scapy.layers.inet import IP, UDP
from scapy.layers.inet6 import IPv6
from scapy.layers.l2 import Dot1Q, Ether
from scapy.packet import Raw

from analyzer import CaptureError, analyze_capture
from analyzer.models import ID_CONTENT, ID_HEADER, ID_PORT, ID_TRANSPORT, ID_UNKNOWN
from analyzer.parser import detect_format
from tools.capture_builder import CaptureBuilder

from .conftest import CLIENT, RESOLVER, SERVER


def test_pcap_is_parsed(basic):
    analysis, _ = basic
    assert analysis.file_format == "pcap"
    assert analysis.packet_count == 15
    assert analysis.warnings == []


def test_pcapng_gives_identical_results(basic_builder):
    capture, _ = basic_builder
    from_pcap = analyze_capture(capture.to_bytes("pcap"))
    from_pcapng = analyze_capture(capture.to_bytes("pcapng"))
    assert from_pcapng.file_format == "pcapng"
    assert from_pcapng.packet_count == from_pcap.packet_count == 15
    for a, b in zip(from_pcap.packets, from_pcapng.packets):
        assert (a.frame, a.src_ip, a.dst_ip, a.src_port, a.dst_port, a.protocol, a.wire_length) == \
               (b.frame, b.src_ip, b.dst_ip, b.src_port, b.dst_port, b.protocol, b.wire_length)
        assert a.timestamp == pytest.approx(b.timestamp, abs=1e-6)
    assert [t.transaction_id for t in from_pcapng.transactions] == ["T0001", "T0002"]


def test_frame_numbers_follow_file_order(basic):
    analysis, frames = basic
    assert [p.frame for p in analysis.packets] == list(range(1, 16))
    assert analysis.packet(frames["syn"]).tcp_flags == 0x02
    assert analysis.packet(frames["get"]).protocol == "HTTP"
    assert analysis.packet(0) is None and analysis.packet(16) is None


def test_timestamps_and_duration(basic):
    analysis, _ = basic
    assert analysis.start_time == pytest.approx(1_700_000_000.001, abs=1e-6)
    timestamps = [p.timestamp for p in analysis.packets]
    assert timestamps == sorted(timestamps)
    assert analysis.duration == pytest.approx(analysis.packets[-1].timestamp - analysis.packets[0].timestamp)
    assert analysis.duration == pytest.approx(0.192, abs=1e-5)


def test_addresses_ports_and_lengths(basic):
    analysis, frames = basic
    get = analysis.packet(frames["get"])
    assert (get.src_ip, get.dst_ip, get.src_port, get.dst_port) == (CLIENT, SERVER, 50000, 80)
    assert get.ip_version == 4 and get.transport == "TCP"
    assert get.wire_length == 14 + 20 + 20 + get.payload_length
    dns = analysis.packet(frames["dns_query"])
    assert (dns.src_ip, dns.dst_ip, dns.dst_port) == (CLIENT, RESOLVER, 53)


def test_protocol_identification_levels(basic):
    analysis, frames = basic
    assert analysis.packet(frames["dns_query"]).protocol == "DNS"
    assert analysis.packet(frames["dns_query"]).identification == ID_CONTENT
    assert "example.com" in analysis.packet(frames["dns_reply"]).info
    assert analysis.packet(frames["syn"]).protocol == "TCP"
    assert analysis.packet(frames["syn"]).identification == ID_TRANSPORT
    assert analysis.packet(frames["get"]).identification == ID_CONTENT


def test_arp_icmp_and_port_guess_are_distinguished():
    capture = CaptureBuilder()
    arp = capture.arp_request("10.0.0.5", "10.0.0.1")
    ping, pong = capture.ping("10.0.0.5", "8.8.8.8")
    quic = capture.add(Ether() / IP(src="10.0.0.5", dst="8.8.8.8") / UDP(sport=40000, dport=443) / Raw(b"\xc0" * 30))
    plain = capture.add(Ether() / IP(src="10.0.0.5", dst="8.8.8.8") / UDP(sport=40000, dport=9999) / Raw(b"x" * 10))
    odd = capture.add(Ether(type=0x1234) / Raw(b"\x00" * 30))
    analysis = analyze_capture(capture.to_bytes())
    assert (analysis.packet(arp).protocol, analysis.packet(arp).identification) == ("ARP", ID_HEADER)
    assert "Who has 10.0.0.1" in analysis.packet(arp).info
    assert analysis.packet(ping).protocol == "ICMP" and "Echo request" in analysis.packet(ping).info
    assert "Echo reply" in analysis.packet(pong).info
    assert (analysis.packet(quic).protocol, analysis.packet(quic).identification) == ("QUIC", ID_PORT)
    assert (analysis.packet(plain).protocol, analysis.packet(plain).identification) == ("UDP", ID_TRANSPORT)
    assert (analysis.packet(odd).protocol, analysis.packet(odd).identification) == ("Other", ID_UNKNOWN)


def test_ipv6_and_vlan_are_decoded():
    capture = CaptureBuilder()
    v6 = capture.add(Ether() / IPv6(src="2001:db8::1", dst="2001:db8::2") / UDP(sport=1111, dport=2222) / Raw(b"hi"))
    vlan = capture.add(Ether() / Dot1Q(vlan=7) / IP(src="10.1.1.1", dst="10.1.1.2") / UDP(sport=1, dport=2) / Raw(b"hi"))
    analysis = analyze_capture(capture.to_bytes())
    assert analysis.packet(v6).ip_version == 6
    assert (analysis.packet(v6).src_ip, analysis.packet(v6).dst_port) == ("2001:db8::1", 2222)
    assert analysis.packet(v6).payload_length == 2
    assert (analysis.packet(vlan).src_ip, analysis.packet(vlan).dst_port) == ("10.1.1.1", 2)


def test_ethernet_padding_is_not_counted_as_payload():
    capture = CaptureBuilder()
    from scapy.layers.inet import TCP
    padded = Ether() / IP(src="10.0.0.1", dst="10.0.0.2") / TCP(sport=1, dport=2, flags="A")
    frame = capture.add(Ether(bytes(padded) + b"\x00" * 6))        # 54 bytes padded to 60
    analysis = analyze_capture(capture.to_bytes())
    assert analysis.packet(frame).captured_length == 60
    assert analysis.packet(frame).payload_length == 0


# ---- invalid input ---------------------------------------------------------
def test_empty_file_is_rejected():
    with pytest.raises(CaptureError, match="empty"):
        analyze_capture(b"")


@pytest.mark.parametrize("data", [b"this is definitely not a capture file", b"\x89PNG\r\n\x1a\n" + b"\x00" * 64, b"abc"])
def test_non_capture_file_is_rejected(data):
    with pytest.raises(CaptureError, match="not a PCAP"):
        analyze_capture(data)


def test_truncated_global_header_is_rejected():
    with pytest.raises(CaptureError, match="truncated"):
        analyze_capture(b"\xd4\xc3\xb2\xa1\x02\x00\x04\x00")


def test_valid_capture_without_packets():
    header = struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1)
    analysis = analyze_capture(header)
    assert analysis.packet_count == 0
    assert analysis.duration == 0.0 and analysis.start_time is None
    assert any("no packets" in warning for warning in analysis.warnings)
    assert analysis.transactions == []


def test_capture_cut_in_the_middle_of_a_frame(basic_builder):
    capture, _ = basic_builder
    data = capture.to_bytes("pcap")
    analysis = analyze_capture(data[:-10])
    assert analysis.packet_count == 14                       # the damaged last frame is dropped
    assert any("ends in the middle of frame 15" in warning for warning in analysis.warnings)


def test_truncated_pcapng_keeps_earlier_frames(basic_builder):
    capture, _ = basic_builder
    data = capture.to_bytes("pcapng")
    analysis = analyze_capture(data[:-10])
    assert analysis.packet_count == 14
    assert analysis.warnings


def _raw_pcap(frames, link_type=1):
    """Hand-written PCAP file, for frames that Scapy itself would refuse to build."""
    data = struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, link_type)
    for number, frame in enumerate(frames):
        data += struct.pack("<IIII", 1_700_000_000 + number, 0, len(frame), len(frame)) + frame
    return data


def test_frame_truncated_inside_headers_does_not_crash():
    full = bytes(Ether() / IP(src="10.0.0.1", dst="10.0.0.2") / UDP())
    analysis = analyze_capture(_raw_pcap([full[:20], full[:6], full[:38]]))
    assert analysis.packet_count == 3
    assert "truncated IPv4 header" in analysis.packets[0].decode_error
    assert "truncated Ethernet header" in analysis.packets[1].decode_error
    assert analysis.packets[1].protocol == "Unknown"
    assert "truncated UDP header" in analysis.packets[2].decode_error
    assert analysis.packets[2].src_ip == "10.0.0.1" and analysis.packets[2].src_port is None


def test_unsupported_link_type_is_reported_not_guessed():
    analysis = analyze_capture(_raw_pcap([b"\x01\x02\x03\x04"], link_type=147))    # 147 = user-defined
    assert analysis.packet_count == 1
    assert analysis.packets[0].protocol == "Unsupported link type"
    assert analysis.packets[0].src_ip == ""
    assert any("Unsupported link-layer" in warning for warning in analysis.warnings)


def test_max_packets_limit(basic_builder):
    capture, _ = basic_builder
    analysis = analyze_capture(capture.to_bytes(), max_packets=5)
    assert analysis.packet_count == 5
    assert any("first 5 frames" in warning for warning in analysis.warnings)


def test_detect_format():
    assert detect_format(b"\x0a\x0d\x0d\x0a" + b"\x00" * 30) == "pcapng"
    assert detect_format(b"\xa1\xb2\x3c\x4d" + b"\x00" * 30) == "pcap"
