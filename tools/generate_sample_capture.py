"""Generate the bundled sample captures (samples/sample_http.pcap and .pcapng).

The sample is SYNTHETIC: it was crafted with Scapy so that every dashboard
feature has something to show (slow request, HTTP errors, a request without a
response, segmentation, a retransmission, a reset, HTTPS metadata, DNS...).
It is analysed by exactly the same engine as a real capture.

Run from the project root:   python -m tools.generate_sample_capture
"""

from __future__ import annotations

from pathlib import Path

from scapy.layers.inet import IP, UDP
from scapy.layers.l2 import Ether
from scapy.packet import Raw

from tools.capture_builder import (CLIENT_MAC, SERVER_MAC, CaptureBuilder, TcpConversation, http_request, http_response,
                                   tls_application_data, tls_client_hello, tls_server_hello)

CLIENT = "192.168.1.20"
GATEWAY = "192.168.1.1"
SHOP, API, CDN, NEWS, SECURE, LEGACY = ("203.0.113.10", "203.0.113.25", "198.51.100.40",
                                        "198.51.100.77", "192.0.2.50", "192.0.2.99")


def build_sample() -> CaptureBuilder:
    capture = CaptureBuilder(start_time=1_767_261_600.0)        # 2026-01-01 10:00:00 UTC
    capture.arp_request(CLIENT, GATEWAY)
    capture.dns_lookup(CLIENT, GATEWAY, "shop.example.com", SHOP, delay=0.02)

    # --- shop: keep-alive connection, page + assets, one 404, a POST with a cookie
    shop = TcpConversation(capture, CLIENT, SHOP, 49152, client_isn=1_000_000, server_isn=7_000_000)
    shop.handshake(delay=0.01)
    shop.client(http_request("GET", "/", "shop.example.com"))
    shop.ack(False)
    shop.server(http_response(200, "OK", b"<html>" + b"<p>Welcome to the shop</p>" * 40 + b"</html>"), delay=0.042)
    shop.ack(True)
    shop.client(http_request("GET", "/static/style.css", "shop.example.com"), delay=0.015)
    shop.server(http_response(200, "OK", b"body{margin:0}" * 30, content_type="text/css"), delay=0.018)
    shop.ack(True)
    shop.client(http_request("GET", "/images/banner-old.png", "shop.example.com"), delay=0.01)
    shop.server(http_response(404, "Not Found", b"<h1>404 Not Found</h1>"), delay=0.009)
    shop.ack(True)

    capture.dns_lookup(CLIENT, GATEWAY, "cdn.example.net", CDN, client_port=53001, delay=0.03)
    capture.ping(CLIENT, GATEWAY)

    # --- cdn: large response split over 6 segments, with one retransmitted segment
    cdn = TcpConversation(capture, CLIENT, CDN, 49153, client_isn=22_000, server_isn=88_000)
    cdn.handshake(delay=0.01)
    cdn.client(http_request("GET", "/assets/app.bundle.js", "cdn.example.net"))
    script = http_response(200, "OK", b"function a(){return 42};" * 340, content_type="application/javascript")
    segment_size, position = 1400, 0
    while position < len(script):
        part = script[position:position + segment_size]
        sequence = cdn.server_seq
        cdn.server(part, delay=0.031 if position == 0 else 0.004)
        if position == 2 * segment_size:
            cdn.resend(False, part, sequence, delay=0.0002)      # duplicate copy of the 3rd segment
        cdn.ack(True)
        position += segment_size
    cdn.close()

    # --- shop again: login POST carrying a cookie over plain HTTP, redirect answer
    shop.client(http_request("POST", "/account/login?next=/cart", "shop.example.com",
                             body=b"username=demo&password=demo-password",
                             extra_headers="Cookie: session=demo-session-id\r\nContent-Type: application/x-www-form-urlencoded\r\n"),
                delay=0.25)
    shop.server(http_response(302, "Found", extra_headers="Location: /cart\r\nSet-Cookie: session=demo-session-id-2\r\n"),
                delay=0.085)
    shop.ack(True)

    # --- api: JSON calls, one slow, one 500, chunked answer
    capture.dns_lookup(CLIENT, GATEWAY, "api.example.com", API, client_port=53002, delay=0.02)
    api = TcpConversation(capture, CLIENT, API, 49154, server_port=8080, client_isn=555_000, server_isn=999_000)
    api.handshake(delay=0.01)
    api.client(http_request("GET", "/v1/products?category=books&page=1", "api.example.com:8080"))
    api.server(http_response(200, "OK", b'{"items":[' + b'{"id":1,"name":"Book"},' * 20 + b'{"id":99}]}',
                             content_type="application/json", chunked=True), delay=0.064)
    api.ack(True)
    api.client(http_request("GET", "/v1/reports/annual", "api.example.com:8080"), delay=0.05)
    api.ack(False)
    api.server(http_response(200, "OK", b'{"report":"' + b"x" * 600 + b'"}', content_type="application/json"), delay=1.84)
    api.ack(True)
    api.client(http_request("PUT", "/v1/cart/items/7", "api.example.com:8080", body=b'{"quantity":2}',
                            extra_headers="Content-Type: application/json\r\nAuthorization: Bearer demo-token\r\n"),
               delay=0.03)
    api.server(http_response(500, "Internal Server Error", b'{"error":"database unavailable"}',
                             content_type="application/json"), delay=0.31)
    api.ack(True)
    api.client(http_request("DELETE", "/v1/cart/items/3", "api.example.com:8080"), delay=0.04)
    api.server(http_response(204, "No Content"), delay=0.022)
    api.ack(True)

    # --- HTTPS: only metadata is visible
    capture.dns_lookup(CLIENT, GATEWAY, "secure.example.org", SECURE, client_port=53003, delay=0.05)
    for port, name, sizes in ((49160, "secure.example.org", (310, 1380, 1380, 620)),
                              (49161, "payments.example.org", (220, 900))):
        tls = TcpConversation(capture, CLIENT, SECURE, port, server_port=443, client_isn=port * 10, server_isn=port * 20)
        tls.handshake(delay=0.02)
        tls.client(tls_client_hello(name))
        tls.server(tls_server_hello(tls13=True), delay=0.027)
        tls.ack(True)
        tls.client(tls_application_data(180), delay=0.004)
        for size in sizes:
            tls.server(tls_application_data(size), delay=0.006)
            tls.ack(True)
        tls.close()

    # --- news: request that never gets an answer (capture of that connection just stops)
    capture.dns_lookup(CLIENT, GATEWAY, "news.example.com", NEWS, client_port=53004, delay=0.04)
    news = TcpConversation(capture, CLIENT, NEWS, 49170, client_isn=31_000, server_isn=41_000)
    news.handshake(delay=0.01)
    news.client(http_request("GET", "/headlines", "news.example.com"))
    news.server(http_response(200, "OK", b"<ul><li>Headline</li></ul>" * 10), delay=0.12)
    news.ack(True)
    news.client(http_request("GET", "/live/stream", "news.example.com"), delay=0.02)
    news.ack(False)

    # --- legacy server: resets the connection instead of answering
    legacy = TcpConversation(capture, CLIENT, LEGACY, 49171, client_isn=61_000, server_isn=71_000)
    legacy.handshake(delay=0.06)
    legacy.client(http_request("GET", "/old/index.cgi", "legacy.example.com"))
    legacy.reset(from_client=False, delay=0.03)

    # --- background noise: failed DNS lookup, NTP, an unidentified UDP datagram
    capture.dns_lookup(CLIENT, GATEWAY, "typo.exmaple.com", None, client_port=53005, delay=0.03)
    capture.add(Ether(src=CLIENT_MAC, dst=SERVER_MAC) / IP(src=CLIENT, dst="192.0.2.123") / UDP(sport=123, dport=123) / Raw(b"\x23" + b"\x00" * 47), 0.02)
    capture.add(Ether(src=CLIENT_MAC, dst=SERVER_MAC) / IP(src=CLIENT, dst="192.0.2.200") / UDP(sport=40001, dport=40002) / Raw(b"\x01\x02\x03\x04" * 8), 0.02)

    # --- shop: last request, then a clean close
    shop.client(http_request("GET", "/cart", "shop.example.com", extra_headers="Cookie: session=demo-session-id-2\r\n"), delay=0.4)
    shop.server(http_response(200, "OK", b"<html>Your cart has 2 items</html>"), delay=0.61)
    shop.ack(True)
    shop.close()
    api.close()
    return capture


def main() -> None:
    folder = Path(__file__).resolve().parent.parent / "samples"
    folder.mkdir(exist_ok=True)
    capture = build_sample()
    capture.write(str(folder / "sample_http.pcap"), "pcap")
    capture.write(str(folder / "sample_http.pcapng"), "pcapng")
    print(f"Wrote {len(capture.packets)} packets to {folder / 'sample_http.pcap'} and .pcapng")


if __name__ == "__main__":
    main()
