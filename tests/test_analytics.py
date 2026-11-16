"""Statistics, filters and insights."""

import pandas as pd
import pytest

from analyzer import analyze_capture
from analyzer import analytics
from tools.capture_builder import CaptureBuilder, TcpConversation, http_request, http_response

from .conftest import CLIENT, RESOLVER, SERVER


@pytest.fixture
def tables(basic):
    analysis, frames = basic
    return analysis, frames, analytics.packets_dataframe(analysis), analytics.transactions_dataframe(analysis)


def test_capture_summary(tables):
    analysis, _, packets, _ = tables
    summary = analytics.capture_summary(analysis, packets)
    assert summary["packet_count"] == 15
    assert summary["unique_ips"] == 3                              # client, server, resolver
    assert summary["http_transactions"] == 2 and summary["http_complete"] == 2
    assert summary["tcp_streams"] == 1
    assert summary["total_bytes"] == sum(p.wire_length for p in analysis.packets)
    assert summary["duration"] == pytest.approx(0.192, abs=1e-5)
    assert summary["packets_per_second"] == pytest.approx(15 / summary["duration"])


def test_protocol_distribution_sums_to_packet_count(tables):
    _, _, packets, _ = tables
    distribution = analytics.protocol_distribution(packets)
    assert distribution["packets"].sum() == 15
    counts = dict(zip(distribution["protocol"], distribution["packets"]))
    assert counts == {"TCP": 9, "HTTP": 4, "DNS": 2}
    assert distribution["packet_share"].sum() == pytest.approx(1.0)
    labels = dict(zip(distribution["protocol"], distribution["identification"]))
    assert labels["HTTP"] == "Verified from payload" and labels["TCP"].startswith("Transport only")


def test_traffic_over_time_preserves_totals(tables):
    _, _, packets, _ = tables
    series, bin_size = analytics.traffic_over_time(packets)
    assert bin_size > 0
    assert series["packets"].sum() == 15
    assert series["bytes"].sum() == packets["length"].sum()
    assert (series["time"].diff().dropna() - bin_size).abs().max() < 1e-9      # evenly spaced, gaps kept as zero


def test_endpoint_statistics(tables):
    _, _, packets, _ = tables
    endpoints = analytics.endpoint_statistics(packets).set_index("ip")
    assert set(endpoints.index) == {CLIENT, SERVER, RESOLVER}
    assert endpoints.loc[RESOLVER, "packets_sent"] == 1 and endpoints.loc[RESOLVER, "packets_received"] == 1
    assert endpoints["packets_sent"].sum() == endpoints["packets_received"].sum() == 15
    pairs = analytics.conversations(packets)
    assert len(pairs) == 2 and pairs["packets"].sum() == 15


def test_transactions_table(tables):
    _, frames, _, transactions = tables
    row = transactions.set_index("id").loc["T0001"]
    assert row["method"] == "GET" and row["status"] == 200 and row["state"] == "Complete"
    assert row["request_frame"] == frames["get"] and row["response_frame"] == frames["get_response"]
    assert row["response_time_ms"] == pytest.approx(50.0, abs=0.01)


def test_packet_filters(tables):
    _, frames, packets, _ = tables
    assert len(analytics.filter_packets(packets, protocols=["DNS"])) == 2
    assert len(analytics.filter_packets(packets, ip=RESOLVER)) == 2
    assert len(analytics.filter_packets(packets, port=80)) == 13
    assert len(analytics.filter_packets(packets, port=80, protocols=["HTTP"])) == 4
    assert list(analytics.filter_packets(packets, search="/login")["frame"]) == [frames["post"]]
    assert list(analytics.filter_packets(packets, frame_range=(3, 5))["frame"]) == [3, 4, 5]
    assert len(analytics.filter_packets(packets, stream=0)) == 13
    assert len(analytics.filter_packets(packets, ip="203.0.113.99")) == 0


def test_transaction_filters():
    capture = CaptureBuilder()
    tcp = TcpConversation(capture, CLIENT, SERVER, 50000)
    tcp.handshake()
    for method, uri, status, delay in [("GET", "/a", 200, 0.01), ("POST", "/b", 500, 0.8),
                                       ("GET", "/c", 404, 0.2), ("GET", "/d", 200, 0.05)]:
        tcp.client(http_request(method, uri, "shop.example", body=b"x" if method == "POST" else b""))
        tcp.server(http_response(status, "X", b"body"), delay=delay)
    tcp.client(http_request("GET", "/pending", "api.example"))
    table = analytics.transactions_dataframe(analyze_capture(capture.to_bytes()))

    assert list(analytics.filter_transactions(table, methods=["POST"])["uri"]) == ["/b"]
    assert list(analytics.filter_transactions(table, status_codes=[404])["uri"]) == ["/c"]
    assert list(analytics.filter_transactions(table, status_classes=["4xx", "5xx"])["uri"]) == ["/b", "/c"]
    assert list(analytics.filter_transactions(table, status_classes=["No response"])["uri"]) == ["/pending"]
    assert list(analytics.filter_transactions(table, hosts=["api.example"])["uri"]) == ["/pending"]
    assert list(analytics.filter_transactions(table, response_time_ms=(100, 1000))["uri"]) == ["/b", "/c"]
    assert list(analytics.filter_transactions(table, states=["No response"])["uri"]) == ["/pending"]
    assert len(analytics.filter_transactions(table, port=80)) == 5
    assert len(analytics.filter_transactions(table, port=81)) == 0
    assert len(analytics.filter_transactions(table, ip=SERVER, methods=["GET"], status_classes=["2xx"])) == 2
    stats = analytics.response_time_statistics(table)
    assert stats["count"] == 4 and stats["max"] == pytest.approx(800, abs=0.01)
    assert stats["min"] == pytest.approx(10, abs=0.01)


def test_insights_report_slow_errors_and_missing_with_evidence():
    capture = CaptureBuilder()
    tcp = TcpConversation(capture, CLIENT, SERVER, 50000)
    tcp.handshake()
    tcp.client(http_request("GET", "/fast", "example.com", extra_headers="Cookie: session=abc\r\n"))
    tcp.server(http_response(200, "OK", b"ok"), delay=0.01)
    slow_request = tcp.client(http_request("GET", "/slow", "example.com"))
    slow_response = tcp.server(http_response(500, "Internal Server Error", b"err"), delay=1.5)
    pending = tcp.client(http_request("GET", "/pending", "example.com"))
    analysis = analyze_capture(capture.to_bytes())
    insights = {insight.title: insight for insight in analytics.build_insights(analysis, slow_threshold_seconds=0.5)}

    slow = insights["1 slow HTTP transaction(s)"]
    assert slow.transaction_ids == ["T0002"] and slow.frames == [slow_request, slow_response]
    assert "1500.0 ms" in slow.detail
    assert insights["1 HTTP server error (5xx) response(s)"].severity == "critical"
    assert insights["1 HTTP request(s) without a response"].frames == [pending]
    assert insights["1 unencrypted request(s) carry credentials or cookies"].transaction_ids == ["T0001"]
    # With a higher threshold the same capture has no slow transaction.
    titles = [i.title for i in analytics.build_insights(analysis, slow_threshold_seconds=2.0)]
    assert "No slow HTTP transactions" in titles


def test_empty_capture_tables_do_not_crash():
    import struct
    analysis = analyze_capture(struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1))
    packets = analytics.packets_dataframe(analysis)
    assert packets.empty
    assert analytics.capture_summary(analysis, packets)["unique_ips"] == 0
    assert analytics.protocol_distribution(packets).empty
    assert analytics.traffic_over_time(packets)[0].empty
    assert analytics.endpoint_statistics(packets).empty
    assert analytics.transactions_dataframe(analysis).empty
    assert analytics.build_insights(analysis) == []
    assert isinstance(analytics.streams_dataframe(analysis), pd.DataFrame)
