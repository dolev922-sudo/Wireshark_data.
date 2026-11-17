"""HTTP reconstruction: GET/POST, matching, frame numbers, response times, TCP edge cases."""

import pytest

from analyzer import analyze_capture
from tools.capture_builder import CaptureBuilder, TcpConversation, http_request, http_response

from .conftest import CLIENT, SERVER

OTHER_SERVER = "198.51.100.7"


def _open(capture, port=50000, server=SERVER, **kwargs):
    tcp = TcpConversation(capture, CLIENT, server, port, **kwargs)
    tcp.handshake()
    return tcp


# ---- basic GET / POST --------------------------------------------------------
def test_http_get_fields(basic):
    analysis, frames = basic
    get = analysis.transaction("T0001")
    assert (get.method, get.host, get.uri, get.status_code) == ("GET", "example.com", "/index.html", 200)
    assert (get.client_ip, get.client_port, get.server_ip, get.server_port) == (CLIENT, 50000, SERVER, 80)
    assert get.request_frame == frames["get"]
    assert get.response_frame == frames["get_response"]
    assert get.match_confidence == "confirmed" and get.is_complete and get.warnings == []
    assert get.response.header("content-length") == "18"
    assert get.response.body_length == 18


def test_http_post_fields(basic):
    analysis, frames = basic
    post = analysis.transaction("T0002")
    assert (post.method, post.uri, post.status_code) == ("POST", "/login", 302)
    assert post.request.body_length == len(b"user=alice&pw=secret")
    assert post.request.framing == "content-length"
    assert post.response.header("Location") == "/home"
    assert (post.request_frame, post.response_frame) == (frames["post"], frames["post_response"])
    assert post.index_in_stream == 2


def test_response_time_is_frame_timestamp_difference(basic):
    analysis, frames = basic
    get, post = analysis.transactions
    assert get.response_time == pytest.approx(0.050, abs=1e-5)
    assert post.response_time == pytest.approx(0.120, abs=1e-5)
    expected = analysis.packet(frames["get_response"]).timestamp - analysis.packet(frames["get"]).timestamp
    assert get.response_time == pytest.approx(expected)
    assert get.request_timestamp == analysis.packet(frames["get"]).timestamp
    assert get.time_to_first_byte == pytest.approx(get.response_time)       # single-segment response


def test_packets_are_labelled_http(basic):
    analysis, frames = basic
    assert analysis.packet(frames["get"]).info == "GET /index.html HTTP/1.1"
    assert analysis.packet(frames["post_response"]).info == "HTTP/1.1 302 Found"
    assert analysis.streams[0].app_protocol == "HTTP"


# ---- TCP segmentation --------------------------------------------------------
def test_response_split_across_segments():
    capture = CaptureBuilder()
    tcp = _open(capture)
    request_frame = tcp.client(http_request("GET", "/big", "example.com"))
    body = bytes(range(256)) * 12                                   # 3072 bytes
    response = http_response(200, "OK", body, content_type="application/octet-stream")
    first = tcp.server(response[:1000], delay=0.030)
    tcp.server(response[1000:2000], delay=0.010)
    last = tcp.server(response[2000:], delay=0.010)
    tcp.close()
    analysis = analyze_capture(capture.to_bytes())

    (transaction,) = analysis.transactions
    assert transaction.response.body_length == 3072 and transaction.is_complete
    assert transaction.response_first_frame == first
    assert transaction.response_frame == last                       # Wireshark shows it on the last segment
    assert transaction.response.frames == [first, first + 1, last]
    assert transaction.time_to_first_byte == pytest.approx(0.030, abs=1e-5)
    assert transaction.response_time == pytest.approx(0.050, abs=1e-5)
    assert transaction.request_frame == request_frame
    assert analysis.packet(last).protocol == "HTTP"
    assert analysis.packet(first).protocol == "TCP" and "reassembled" in analysis.packet(first).info


def test_request_headers_split_mid_line():
    capture = CaptureBuilder()
    tcp = _open(capture)
    request = http_request("POST", "/upload", "example.com", body=b"A" * 300)
    tcp.client(request[:7])                                          # "POST /u"
    tcp.client(request[7:60])
    last_request = tcp.client(request[60:])
    response_frame = tcp.server(http_response(201, "Created"), delay=0.02)
    analysis = analyze_capture(capture.to_bytes())
    (transaction,) = analysis.transactions
    assert (transaction.method, transaction.uri, transaction.status_code) == ("POST", "/upload", 201)
    assert transaction.request.body_length == 300
    assert (transaction.request_frame, transaction.response_frame) == (last_request, response_frame)
    assert transaction.response_time == pytest.approx(0.02, abs=1e-5)


def test_two_messages_in_one_segment_and_keep_alive_order():
    capture = CaptureBuilder()
    tcp = _open(capture)
    both = http_request("GET", "/a", "example.com") + http_request("GET", "/b", "example.com")
    pipelined = tcp.client(both)                                     # pipelining: two requests, one frame
    response_a = tcp.server(http_response(200, "OK", b"AAAA"), delay=0.01)
    response_b = tcp.server(http_response(404, "Not Found", b"nope"), delay=0.01)
    third = tcp.client(http_request("GET", "/c", "example.com"), delay=0.01)
    response_c = tcp.server(http_response(500, "Internal Server Error", b"boom"), delay=0.2)
    analysis = analyze_capture(capture.to_bytes())

    assert [(t.uri, t.status_code) for t in analysis.transactions] == [("/a", 200), ("/b", 404), ("/c", 500)]
    assert [t.request_frame for t in analysis.transactions] == [pipelined, pipelined, third]
    assert [t.response_frame for t in analysis.transactions] == [response_a, response_b, response_c]
    assert [t.index_in_stream for t in analysis.transactions] == [1, 2, 3]
    assert "GET /a HTTP/1.1 | GET /b HTTP/1.1" == analysis.packet(pipelined).info


# ---- retransmission / reordering --------------------------------------------
def test_retransmitted_segments_are_ignored():
    capture = CaptureBuilder()
    tcp = _open(capture)
    request = http_request("GET", "/r", "example.com")
    request_sequence = tcp.client_seq
    original = tcp.client(request)
    duplicate = tcp.resend(True, request, request_sequence, delay=0.2)      # same bytes again
    response = http_response(200, "OK", b"0123456789")
    response_sequence = tcp.server_seq
    response_frame = tcp.server(response, delay=0.05)
    duplicate_response = tcp.resend(False, response, response_sequence, delay=0.3)
    analysis = analyze_capture(capture.to_bytes())

    (transaction,) = analysis.transactions                           # not two transactions
    assert transaction.request_frame == original
    assert transaction.response_frame == response_frame
    assert transaction.response.body_length == 10
    assert transaction.response_time == pytest.approx(0.25, abs=1e-5)       # measured from the original frames
    stream = analysis.streams[0]
    assert stream.client.retransmitted_frames == [duplicate]
    assert stream.server.retransmitted_frames == [duplicate_response]
    assert analysis.packet(duplicate).tcp_analysis == "retransmission"
    assert "[TCP Retransmission]" in analysis.packet(duplicate).info
    assert stream.client.gap_bytes == stream.server.gap_bytes == 0


def test_out_of_order_segments_are_put_back_in_sequence():
    capture = CaptureBuilder()
    tcp = _open(capture)
    tcp.client(http_request("GET", "/ooo", "example.com"))
    body = b"".join(bytes([65 + i]) * 500 for i in range(3))         # AAA..BBB..CCC..
    response = http_response(200, "OK", body)
    part1, part2, part3 = response[:400], response[400:900], response[900:]
    base = tcp.server_seq
    first = tcp.resend(False, part1, base, delay=0.01)
    third = tcp.resend(False, part3, base + 900, delay=0.01)         # arrives before part 2
    second = tcp.resend(False, part2, base + 400, delay=0.01)
    tcp.lose(False, len(response))                                   # keep the helper's counter in sync
    analysis = analyze_capture(capture.to_bytes())

    (transaction,) = analysis.transactions
    assert transaction.is_complete and transaction.response.body_length == 1500
    assert analysis.streams[0].server.chunks[0] == response          # byte-exact reconstruction
    assert analysis.streams[0].server.out_of_order_frames == [second]
    assert analysis.streams[0].server.gap_bytes == 0
    assert transaction.response_first_frame == first
    assert transaction.response_frame == second                      # complete only when the late segment arrives
    assert transaction.response.frames == [first, second, third]
    assert transaction.response_time == pytest.approx(0.03, abs=1e-5)


def test_sequence_number_wraparound():
    capture = CaptureBuilder()
    tcp = _open(capture, client_isn=2**32 - 20, server_isn=2**32 - 30)
    tcp.client(http_request("GET", "/wrap", "example.com"))
    response = http_response(200, "OK", b"x" * 100)
    tcp.server(response[:50], delay=0.01)
    tcp.server(response[50:], delay=0.01)
    analysis = analyze_capture(capture.to_bytes())
    (transaction,) = analysis.transactions
    assert transaction.uri == "/wrap" and transaction.is_complete
    assert analysis.streams[0].has_gaps is False


# ---- multiple connections ----------------------------------------------------
def test_interleaved_connections_are_matched_per_stream():
    capture = CaptureBuilder()
    slow = _open(capture, port=50001)
    fast = _open(capture, port=50002, server=OTHER_SERVER)
    slow_request = slow.client(http_request("GET", "/slow", "slow.example"))
    fast_request = fast.client(http_request("GET", "/fast", "fast.example"), delay=0.001)
    # The FAST response arrives first and is nearest in time to BOTH requests.
    fast_response = fast.server(http_response(200, "OK", b"fast"), delay=0.002)
    slow_response = slow.server(http_response(503, "Service Unavailable", b"slow"), delay=0.9)
    analysis = analyze_capture(capture.to_bytes())

    by_uri = {t.uri: t for t in analysis.transactions}
    assert by_uri["/slow"].status_code == 503 and by_uri["/fast"].status_code == 200
    assert (by_uri["/slow"].request_frame, by_uri["/slow"].response_frame) == (slow_request, slow_response)
    assert (by_uri["/fast"].request_frame, by_uri["/fast"].response_frame) == (fast_request, fast_response)
    assert by_uri["/slow"].stream_id == 0 and by_uri["/fast"].stream_id == 1
    assert by_uri["/slow"].server_ip == SERVER and by_uri["/fast"].server_ip == OTHER_SERVER
    assert by_uri["/slow"].response_time == pytest.approx(0.903, abs=1e-5)


def test_port_reuse_starts_a_new_stream():
    capture = CaptureBuilder()
    first = _open(capture, port=50009, client_isn=100, server_isn=200)
    first.client(http_request("GET", "/one", "example.com"))
    first.server(http_response(200, "OK", b"1"))
    first.close()
    second = _open(capture, port=50009, client_isn=900000, server_isn=800000)   # same 4-tuple again
    second.client(http_request("GET", "/two", "example.com"))
    second.server(http_response(204, "No Content"))
    analysis = analyze_capture(capture.to_bytes())
    assert len(analysis.streams) == 2
    assert [(t.uri, t.stream_id, t.status_code) for t in analysis.transactions] == [("/one", 0, 200), ("/two", 1, 204)]


# ---- incomplete exchanges ----------------------------------------------------
def test_request_without_response():
    capture = CaptureBuilder()
    tcp = _open(capture)
    answered = tcp.client(http_request("GET", "/ok", "example.com"))
    tcp.server(http_response(200, "OK", b"fine"))
    unanswered = tcp.client(http_request("GET", "/never", "example.com"))
    analysis = analyze_capture(capture.to_bytes())

    done, missing = analysis.transactions
    assert done.request_frame == answered and done.status_code == 200
    assert missing.request_frame == unanswered
    assert missing.response is None and missing.status_code is None
    assert missing.response_frame is None and missing.response_time is None
    assert missing.match_confidence == "none" and not missing.is_complete
    assert any("No response was captured" in warning for warning in missing.warnings)
    assert any("still open" in warning for warning in missing.warnings)


def test_request_followed_by_reset():
    capture = CaptureBuilder()
    tcp = _open(capture)
    tcp.client(http_request("GET", "/rst", "example.com"))
    reset_frame = tcp.reset(from_client=False)
    analysis = analyze_capture(capture.to_bytes())
    (transaction,) = analysis.transactions
    assert transaction.response is None
    assert any("reset" in warning for warning in transaction.warnings)
    assert analysis.streams[0].server.rst_frame == reset_frame


def test_response_body_truncated():
    capture = CaptureBuilder()
    tcp = _open(capture)
    tcp.client(http_request("GET", "/cut", "example.com"))
    response = http_response(200, "OK", b"z" * 5000)
    tcp.server(response[:1200])                                      # capture stops here
    analysis = analyze_capture(capture.to_bytes())
    (transaction,) = analysis.transactions
    assert transaction.status_code == 200                            # headers were seen
    assert transaction.response.declared_length == 5000
    assert transaction.response.complete is False and not transaction.is_complete
    assert any("incomplete" in warning and "5,000" in warning for warning in transaction.warnings)


def test_capture_starting_mid_connection_reports_orphan_response():
    capture = CaptureBuilder()
    tcp = TcpConversation(capture, CLIENT, SERVER, 50000, client_isn=7000, server_isn=9000)   # no handshake
    orphan_frame = tcp.server(http_response(200, "OK", b"late answer"))          # its request was never captured
    request_frame = tcp.client(http_request("GET", "/next", "example.com"), delay=0.01)
    response_frame = tcp.server(http_response(200, "OK", b"next answer"), delay=0.04)
    analysis = analyze_capture(capture.to_bytes())

    orphan, normal = analysis.transactions
    assert orphan.request is None and orphan.response_first_frame == orphan_frame
    assert orphan.response_time is None and orphan.method == ""
    assert any("without a captured request" in warning for warning in orphan.warnings)
    assert (normal.request_frame, normal.response_frame) == (request_frame, response_frame)
    assert normal.client_ip == CLIENT and normal.server_ip == SERVER    # roles come from content, not packet order
    assert analysis.streams[0].client.starts_mid_stream


def test_gap_in_stream_marks_matches_uncertain_without_shifting_pairs():
    capture = CaptureBuilder()
    tcp = _open(capture)
    first_request = tcp.client(http_request("GET", "/1", "example.com"))
    first_response = tcp.server(http_response(200, "OK", b"one"), delay=0.01)
    second_request = tcp.client(http_request("GET", "/2", "example.com"), delay=0.01)
    tcp.lose(False, len(http_response(200, "OK", b"two")))            # response 2 is missing from the capture
    third_request = tcp.client(http_request("GET", "/3", "example.com"), delay=0.05)
    third_response = tcp.server(http_response(404, "Not Found", b"three"), delay=0.01)
    analysis = analyze_capture(capture.to_bytes())

    one, two, three = analysis.transactions
    assert (one.request_frame, one.response_frame, one.match_confidence) == (first_request, first_response, "confirmed")
    assert two.request_frame == second_request and two.response is None      # NOT paired with response 3
    assert any("lost in a capture gap" in warning for warning in two.warnings)
    assert (three.request_frame, three.response_frame, three.status_code) == (third_request, third_response, 404)
    assert three.match_confidence == "uncertain"
    assert any("cannot be proven" in warning for warning in three.warnings)
    assert analysis.streams[0].server.gap_bytes > 0 and analysis.streams[0].has_gaps


# ---- message framing ---------------------------------------------------------
def test_chunked_transfer_encoding():
    capture = CaptureBuilder()
    tcp = _open(capture)
    tcp.client(http_request("GET", "/chunked", "example.com"))
    response = http_response(200, "OK", b"Hello chunked world!", chunked=True)
    tcp.server(response[:60], delay=0.01)
    last = tcp.server(response[60:], delay=0.01)
    follow_up = tcp.client(http_request("GET", "/after", "example.com"))
    tcp.server(http_response(200, "OK", b"after"))
    analysis = analyze_capture(capture.to_bytes())
    chunked, after = analysis.transactions
    assert chunked.response.framing == "chunked" and chunked.response.body_length == 20
    assert chunked.response.complete and chunked.response_frame == last
    assert after.request_frame == follow_up and after.uri == "/after"       # parser stayed aligned after the chunks


def test_head_response_has_no_body_even_with_content_length():
    capture = CaptureBuilder()
    tcp = _open(capture)
    tcp.client(http_request("HEAD", "/file", "example.com"))
    tcp.server(b"HTTP/1.1 200 OK\r\nContent-Length: 99999\r\n\r\n")
    tcp.client(http_request("GET", "/x", "example.com"))
    tcp.server(http_response(200, "OK", b"x"))
    analysis = analyze_capture(capture.to_bytes())
    head, get = analysis.transactions
    assert head.method == "HEAD" and head.response.framing == "none" and head.is_complete
    assert get.uri == "/x" and get.status_code == 200


def test_100_continue_is_not_treated_as_the_answer():
    capture = CaptureBuilder()
    tcp = _open(capture)
    request = http_request("POST", "/big", "example.com", body=b"B" * 50, extra_headers="Expect: 100-continue\r\n")
    header_end = request.index(b"\r\n\r\n") + 4
    tcp.client(request[:header_end])
    tcp.server(b"HTTP/1.1 100 Continue\r\n\r\n", delay=0.005)
    body_frame = tcp.client(request[header_end:], delay=0.005)
    final = tcp.server(http_response(201, "Created"), delay=0.02)
    analysis = analyze_capture(capture.to_bytes())
    (transaction,) = analysis.transactions
    assert transaction.status_code == 201 and transaction.response_frame == final
    assert [m.status_code for m in transaction.informational] == [100]
    assert transaction.request_frame == body_frame


def test_response_without_length_runs_until_close():
    capture = CaptureBuilder()
    tcp = _open(capture)
    tcp.client(http_request("GET", "/old", "example.com"))
    tcp.server(http_response(200, "OK", b"legacy body", with_length=False))
    tcp.send(False, b"", flags="FA")
    analysis = analyze_capture(capture.to_bytes())
    (transaction,) = analysis.transactions
    assert transaction.response.framing == "until-close"
    assert transaction.response.body_length == 11 and transaction.response.complete


def test_http_on_non_standard_port_is_found_by_content():
    capture = CaptureBuilder()
    tcp = TcpConversation(capture, CLIENT, SERVER, 50000, server_port=8081)
    tcp.handshake()
    tcp.client(http_request("GET", "/api", "localhost:8081"))
    tcp.server(http_response(200, "OK", b"{}", content_type="application/json"))
    analysis = analyze_capture(capture.to_bytes())
    (transaction,) = analysis.transactions
    assert transaction.server_port == 8081 and transaction.host == "localhost:8081"


def test_non_http_tcp_payload_creates_no_transactions():
    capture = CaptureBuilder()
    tcp = _open(capture, port=50000)
    tcp.client(b"SSH-2.0-OpenSSH_9.6\r\n")
    tcp.server(b"SSH-2.0-OpenSSH_9.3\r\n")
    analysis = analyze_capture(capture.to_bytes())
    assert analysis.transactions == [] and analysis.tls_sessions == []
    assert analysis.streams[0].app_protocol == ""
    assert {p.protocol for p in analysis.packets} == {"TCP"}
