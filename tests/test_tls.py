"""HTTPS: only TLS handshake metadata may be reported - never invented HTTP content."""

import pytest

from analyzer import analyze_capture
from analyzer.analytics import tls_dataframe
from tools.capture_builder import (CaptureBuilder, TcpConversation, tls_application_data, tls_client_hello,
                                   tls_server_hello)

from .conftest import CLIENT, SERVER


def _https_capture(split_hello=False):
    capture = CaptureBuilder()
    tcp = TcpConversation(capture, CLIENT, SERVER, 51000, server_port=443)
    tcp.handshake()
    hello = tls_client_hello("secure.example.org")
    if split_hello:
        client_hello = tcp.client(hello[:40])
        tcp.client(hello[40:])
    else:
        client_hello = tcp.client(hello)
    server_hello = tcp.server(tls_server_hello(tls13=True), delay=0.025)
    data_frame = tcp.client(tls_application_data(200))
    tcp.server(tls_application_data(900))
    return capture, client_hello, server_hello, data_frame


@pytest.mark.parametrize("split_hello", [False, True])
def test_tls_metadata_is_extracted(split_hello):
    capture, client_hello, server_hello, data_frame = _https_capture(split_hello)
    analysis = analyze_capture(capture.to_bytes())
    (session,) = analysis.tls_sessions
    assert session.server_name == "secure.example.org"
    assert session.alpn == ["h2", "http/1.1"]
    assert session.tls_version == "TLS 1.3"
    assert (session.client_hello_frame, session.server_hello_frame) == (client_hello, server_hello)
    assert (session.client_ip, session.server_ip, session.server_port) == (CLIENT, SERVER, 443)
    assert analysis.packet(data_frame).protocol == "TLS"
    assert "Encrypted" in analysis.packet(data_frame).info
    assert "SNI=secure.example.org" in analysis.packet(client_hello).info
    if not split_hello:
        assert session.handshake_time == pytest.approx(0.025, abs=1e-5)


def test_https_never_produces_http_transactions():
    capture, *_ = _https_capture()
    analysis = analyze_capture(capture.to_bytes())
    assert analysis.transactions == []
    assert analysis.streams[0].app_protocol == "TLS"
    table = tls_dataframe(analysis)
    assert table.loc[0, "server_name"] == "secure.example.org" and table.loc[0, "bytes"] > 1000


def test_tls_1_2_server_hello_and_missing_sni():
    capture = CaptureBuilder()
    tcp = TcpConversation(capture, CLIENT, SERVER, 51001, server_port=8443)
    tcp.handshake()
    hello = tls_client_hello("x")
    tcp.server(tls_server_hello(tls13=False))          # ClientHello not captured
    analysis = analyze_capture(capture.to_bytes())
    (session,) = analysis.tls_sessions
    assert session.tls_version == "TLS 1.2"
    assert session.server_name == "" and session.client_hello_frame is None
    assert tls_dataframe(analysis).loc[0, "server_name"] == "(no SNI)"
    assert hello                                        # (helper used only to document intent)
