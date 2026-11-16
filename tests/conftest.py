"""Shared fixtures: synthetic captures whose correct answers are known in advance."""

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from analyzer import analyze_capture  # noqa: E402
from tools.capture_builder import CaptureBuilder, TcpConversation, http_request, http_response  # noqa: E402

CLIENT, SERVER, RESOLVER = "10.0.0.5", "93.184.216.34", "10.0.0.1"


def build_basic_capture() -> tuple[CaptureBuilder, dict]:
    """DNS lookup + one TCP connection carrying a GET and a POST. Returns frames of interest."""
    capture = CaptureBuilder()
    frames = {}
    frames["dns_query"], frames["dns_reply"] = capture.dns_lookup(CLIENT, RESOLVER, "example.com", SERVER)
    tcp = TcpConversation(capture, CLIENT, SERVER, 50000)
    frames["syn"], frames["syn_ack"], frames["ack"] = tcp.handshake()
    frames["get"] = tcp.client(http_request("GET", "/index.html", "example.com"))
    tcp.ack(False, delay=0.0005)
    frames["get_response"] = tcp.server(http_response(200, "OK", b"<html>hello</html>"), delay=0.0495)   # 50 ms total
    tcp.ack(True)
    frames["post"] = tcp.client(http_request("POST", "/login", "example.com", body=b"user=alice&pw=secret"), delay=0.010)
    frames["post_response"] = tcp.server(http_response(302, "Found", extra_headers="Location: /home\r\n"), delay=0.120)
    tcp.ack(True)
    frames["fin"], _, frames["last"] = tcp.close()
    return capture, frames


@pytest.fixture
def basic():
    capture, frames = build_basic_capture()
    return analyze_capture(capture.to_bytes("pcap"), "basic.pcap"), frames


@pytest.fixture
def basic_builder():
    return build_basic_capture()
