"""Statistics, tables, filters and insights computed from a CaptureAnalysis.

Every number shown in the dashboard is produced here from the decoded packets.
Nothing in this module talks to the AI service.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Iterable, Optional

import pandas as pd

from .models import ID_CONTENT, ID_HEADER, ID_PORT, ID_TRANSPORT, ID_UNKNOWN, CaptureAnalysis
from .parser import tcp_flags_text

IDENTIFICATION_LABELS = {
    ID_CONTENT: "Verified from payload",
    ID_HEADER: "Identified from header",
    ID_PORT: "Guessed from port",
    ID_TRANSPORT: "Transport only (application unknown)",
    ID_UNKNOWN: "Unknown / unsupported",
}
# "Nice" bucket sizes (seconds) for the traffic-over-time chart.
BIN_SIZES = [0.001, 0.002, 0.005, 0.01, 0.02, 0.05, 0.1, 0.2, 0.5, 1, 2, 5, 10, 15, 30,
             60, 120, 300, 600, 900, 1800, 3600, 7200, 21600, 86400]


# --------------------------------------------------------------------------
# Tables
# --------------------------------------------------------------------------
def packets_dataframe(analysis: CaptureAnalysis) -> pd.DataFrame:
    """One row per frame. ``time`` is seconds since the first frame."""
    start = analysis.start_time or 0.0
    rows = [
        (
            p.frame, p.timestamp - start, p.timestamp, p.src_ip, p.dst_ip, p.src_port, p.dst_port,
            p.protocol, p.identification, p.transport, p.wire_length, p.captured_length, p.payload_length,
            tcp_flags_text(p.tcp_flags) if p.transport == "TCP" else "", p.stream_id, p.tcp_analysis, p.info,
        )
        for p in analysis.packets
    ]
    frame = pd.DataFrame(rows, columns=[
        "frame", "time", "epoch", "src_ip", "dst_ip", "src_port", "dst_port", "protocol", "identification",
        "transport", "length", "captured_length", "payload_length", "tcp_flags", "stream", "tcp_analysis", "info",
    ])
    frame["timestamp"] = pd.to_datetime(frame["epoch"], unit="s", utc=True)
    for column in ("src_port", "dst_port", "stream"):
        frame[column] = frame[column].astype("Int64")
    return frame


def transactions_dataframe(analysis: CaptureAnalysis) -> pd.DataFrame:
    """One row per HTTP transaction."""
    start = analysis.start_time or 0.0
    rows = []
    for t in analysis.transactions:
        response_time = t.response_time
        ttfb = t.time_to_first_byte
        if t.request is None:
            state = "Orphan response"
        elif t.response is None:
            state = "No response"
        elif not t.is_complete:
            state = "Incomplete"
        elif t.match_confidence == "uncertain":
            state = "Uncertain match"
        else:
            state = "Complete"
        rows.append({
            "id": t.transaction_id,
            "stream": t.stream_id,
            "method": t.method,
            "host": t.host,
            "uri": t.uri,
            "status": t.status_code,
            "state": state,
            "request_frame": t.request_frame,
            "response_frame": t.response_frame,
            "response_first_frame": t.response_first_frame,
            "request_time": (t.request_timestamp - start) if t.request_timestamp is not None else None,
            "response_at": (t.response_timestamp - start) if t.response_timestamp is not None else None,
            "request_epoch": t.request_timestamp,
            "response_epoch": t.response_timestamp,
            "response_time_ms": response_time * 1000 if response_time is not None else None,
            "ttfb_ms": ttfb * 1000 if ttfb is not None else None,
            "client_ip": t.client_ip,
            "client_port": t.client_port,
            "server_ip": t.server_ip,
            "server_port": t.server_port,
            "content_type": t.response.header("Content-Type") if t.response else "",
            "response_bytes": t.response.body_length if t.response else None,
            "confidence": t.match_confidence,
            "warnings": " ".join(t.warnings),
        })
    columns = [
        "id", "stream", "method", "host", "uri", "status", "state", "request_frame", "response_frame",
        "response_first_frame", "request_time", "response_at", "request_epoch", "response_epoch",
        "response_time_ms", "ttfb_ms", "client_ip", "client_port", "server_ip", "server_port",
        "content_type", "response_bytes", "confidence", "warnings",
    ]
    frame = pd.DataFrame(rows, columns=columns)
    for column in ("status", "request_frame", "response_frame", "response_first_frame", "response_bytes"):
        frame[column] = frame[column].astype("Int64")
    for column in ("request_time", "response_at", "response_time_ms", "ttfb_ms"):
        frame[column] = frame[column].astype("float64")
    return frame


def streams_dataframe(analysis: CaptureAnalysis) -> pd.DataFrame:
    """One row per TCP connection, with its reassembly health."""
    rows = []
    for s in analysis.streams:
        issues = []
        if s.client.starts_mid_stream or s.server.starts_mid_stream:
            issues.append("handshake not captured")
        elif not s.handshake_complete:
            issues.append("handshake incomplete")
        if s.has_gaps:
            issues.append(f"{s.client.gap_bytes + s.server.gap_bytes:,} bytes missing")
        if s.client.rst_frame or s.server.rst_frame:
            issues.append("reset (RST)")
        if not (s.client.fin_frame or s.server.fin_frame or s.client.rst_frame or s.server.rst_frame):
            issues.append("no close captured")
        rows.append({
            "stream": s.stream_id,
            "client": f"{s.client.src_ip}:{s.client.src_port}",
            "server": f"{s.server.src_ip}:{s.server.src_port}",
            "client_ip": s.client.src_ip, "server_ip": s.server.src_ip,
            "client_port": s.client.src_port, "server_port": s.server.src_port,
            "application": s.app_protocol or "Unidentified",
            "packets": len(s.frames),
            "bytes": s.client.payload_bytes + s.server.payload_bytes,
            "first_frame": s.first_frame, "last_frame": s.last_frame,
            "duration": s.last_timestamp - s.first_timestamp,
            "handshake": s.handshake_complete,
            "missing_bytes": s.client.gap_bytes + s.server.gap_bytes,
            "retransmissions": s.retransmissions,
            "out_of_order": s.out_of_order,
            "reset": bool(s.client.rst_frame or s.server.rst_frame),
            "issues": "; ".join(issues),
        })
    return pd.DataFrame(rows, columns=[
        "stream", "client", "server", "client_ip", "server_ip", "client_port", "server_port", "application",
        "packets", "bytes", "first_frame", "last_frame", "duration", "handshake", "missing_bytes",
        "retransmissions", "out_of_order", "reset", "issues",
    ])


def tls_dataframe(analysis: CaptureAnalysis) -> pd.DataFrame:
    rows = [{
        "stream": s.stream_id,
        "server_name": s.server_name or "(no SNI)",
        "client": f"{s.client_ip}:{s.client_port}",
        "server": f"{s.server_ip}:{s.server_port}",
        "tls_version": s.tls_version or "not seen",
        "alpn": ", ".join(s.alpn),
        "client_hello_frame": s.client_hello_frame,
        "server_hello_frame": s.server_hello_frame,
        "handshake_ms": s.handshake_time * 1000 if s.handshake_time is not None else None,
        "bytes": s.client_bytes + s.server_bytes,
    } for s in analysis.tls_sessions]
    frame = pd.DataFrame(rows, columns=[
        "stream", "server_name", "client", "server", "tls_version", "alpn",
        "client_hello_frame", "server_hello_frame", "handshake_ms", "bytes"])
    for column in ("client_hello_frame", "server_hello_frame"):
        frame[column] = frame[column].astype("Int64")
    return frame


# --------------------------------------------------------------------------
# Statistics
# --------------------------------------------------------------------------
def capture_summary(analysis: CaptureAnalysis, packets: pd.DataFrame) -> dict:
    """Headline numbers for the Overview page."""
    addresses = pd.concat([packets["src_ip"], packets["dst_ip"]])
    addresses = addresses[addresses != ""]
    total_bytes = int(packets["length"].sum()) if len(packets) else 0
    duration = analysis.duration
    return {
        "file_name": analysis.file_name,
        "file_format": analysis.file_format,
        "file_size": analysis.file_size,
        "sha256": analysis.sha256,
        "packet_count": analysis.packet_count,
        "start_time": analysis.start_time,
        "end_time": analysis.end_time,
        "duration": duration,
        "total_bytes": total_bytes,
        "average_packet_size": total_bytes / analysis.packet_count if analysis.packet_count else 0.0,
        "packets_per_second": analysis.packet_count / duration if duration > 0 else None,
        "bits_per_second": total_bytes * 8 / duration if duration > 0 else None,
        "unique_ips": int(addresses.nunique()),
        "tcp_streams": len(analysis.streams),
        "http_transactions": len(analysis.transactions),
        "http_complete": sum(1 for t in analysis.transactions if t.is_complete),
        "tls_sessions": len(analysis.tls_sessions),
    }


def protocol_distribution(packets: pd.DataFrame) -> pd.DataFrame:
    """Packets and bytes per protocol label, largest first."""
    if packets.empty:
        return pd.DataFrame(columns=["protocol", "packets", "bytes", "packet_share", "identification"])
    grouped = packets.groupby("protocol").agg(
        packets=("frame", "count"), bytes=("length", "sum"),
        identification=("identification", lambda values: values.mode().iat[0]),
    ).reset_index()
    grouped["packet_share"] = grouped["packets"] / grouped["packets"].sum()
    grouped["identification"] = grouped["identification"].map(IDENTIFICATION_LABELS)
    return grouped.sort_values("packets", ascending=False, ignore_index=True)


def choose_bin_size(duration: float, target_bins: int = 80) -> float:
    for size in BIN_SIZES:
        if duration / size <= target_bins:
            return size
    return BIN_SIZES[-1]


def traffic_over_time(packets: pd.DataFrame, target_bins: int = 80) -> tuple[pd.DataFrame, float]:
    """Packets and bytes per time bucket. Returns (table, bucket size in seconds)."""
    if packets.empty:
        return pd.DataFrame(columns=["time", "packets", "bytes"]), 1.0
    duration = float(packets["time"].max() - packets["time"].min())
    bin_size = choose_bin_size(duration, target_bins)
    origin = float(packets["time"].min())
    buckets = ((packets["time"] - origin) // bin_size).astype(int)
    grouped = packets.groupby(buckets).agg(packets=("frame", "count"), bytes=("length", "sum"))
    grouped = grouped.reindex(range(int(buckets.max()) + 1), fill_value=0)     # show quiet periods as zero
    grouped.insert(0, "time", origin + grouped.index * bin_size)
    return grouped.reset_index(drop=True), bin_size


def endpoint_statistics(packets: pd.DataFrame) -> pd.DataFrame:
    """Traffic sent and received by every IP address."""
    with_ip = packets[(packets["src_ip"] != "") & (packets["dst_ip"] != "")]
    if with_ip.empty:
        return pd.DataFrame(columns=["ip", "packets_sent", "packets_received", "bytes_sent",
                                     "bytes_received", "total_packets", "total_bytes"])
    sent = with_ip.groupby("src_ip").agg(packets_sent=("frame", "count"), bytes_sent=("length", "sum"))
    received = with_ip.groupby("dst_ip").agg(packets_received=("frame", "count"), bytes_received=("length", "sum"))
    table = sent.join(received, how="outer").fillna(0).astype(int)
    table["total_packets"] = table["packets_sent"] + table["packets_received"]
    table["total_bytes"] = table["bytes_sent"] + table["bytes_received"]
    table.index.name = "ip"
    return table.sort_values("total_bytes", ascending=False).reset_index()


def conversations(packets: pd.DataFrame) -> pd.DataFrame:
    """Traffic between each pair of IP addresses (direction ignored)."""
    with_ip = packets[(packets["src_ip"] != "") & (packets["dst_ip"] != "")]
    if with_ip.empty:
        return pd.DataFrame(columns=["address_a", "address_b", "packets", "bytes"])
    low = with_ip[["src_ip", "dst_ip"]].min(axis=1)
    high = with_ip[["src_ip", "dst_ip"]].max(axis=1)
    grouped = with_ip.groupby([low, high]).agg(packets=("frame", "count"), bytes=("length", "sum")).reset_index()
    grouped.columns = ["address_a", "address_b", "packets", "bytes"]
    return grouped.sort_values("bytes", ascending=False, ignore_index=True)


# --------------------------------------------------------------------------
# Investigation filters
# --------------------------------------------------------------------------
def _contains_port(frame: pd.DataFrame, columns: tuple[str, str], port: int) -> pd.Series:
    return (frame[columns[0]] == port) | (frame[columns[1]] == port)


def filter_packets(
    packets: pd.DataFrame,
    protocols: Optional[Iterable[str]] = None,
    ip: str = "",
    port: Optional[int] = None,
    search: str = "",
    frame_range: Optional[tuple[int, int]] = None,
    time_range: Optional[tuple[float, float]] = None,
    stream: Optional[int] = None,
    only_tcp_issues: bool = False,
) -> pd.DataFrame:
    """Return the packets that satisfy every given filter."""
    mask = pd.Series(True, index=packets.index)
    protocols = list(protocols or [])
    if protocols:
        mask &= packets["protocol"].isin(protocols)
    if ip.strip():
        needle = ip.strip()
        mask &= packets["src_ip"].str.contains(needle, regex=False) | packets["dst_ip"].str.contains(needle, regex=False)
    if port is not None:
        mask &= _contains_port(packets, ("src_port", "dst_port"), port).fillna(False)
    if stream is not None:
        mask &= (packets["stream"] == stream).fillna(False)
    if frame_range:
        mask &= packets["frame"].between(*frame_range)
    if time_range:
        mask &= packets["time"].between(*time_range)
    if only_tcp_issues:
        mask &= packets["tcp_analysis"] != ""
    if search.strip():
        needle = search.strip().lower()
        text = (packets["info"] + " " + packets["src_ip"] + " " + packets["dst_ip"] + " " + packets["protocol"]).str.lower()
        mask &= text.str.contains(needle, regex=False)
    return packets[mask]


def filter_transactions(
    transactions: pd.DataFrame,
    methods: Optional[Iterable[str]] = None,
    hosts: Optional[Iterable[str]] = None,
    status_codes: Optional[Iterable[int]] = None,
    status_classes: Optional[Iterable[str]] = None,
    ip: str = "",
    port: Optional[int] = None,
    response_time_ms: Optional[tuple[float, float]] = None,
    states: Optional[Iterable[str]] = None,
    search: str = "",
) -> pd.DataFrame:
    """Return the HTTP transactions that satisfy every given filter.

    A response-time range only keeps transactions that *have* a response time.
    ``status_classes`` accepts "1xx" ... "5xx" and "No response".
    """
    mask = pd.Series(True, index=transactions.index)
    methods, hosts = list(methods or []), list(hosts or [])
    status_codes, status_classes, states = list(status_codes or []), list(status_classes or []), list(states or [])
    if methods:
        mask &= transactions["method"].isin(methods)
    if hosts:
        mask &= transactions["host"].isin(hosts)
    if status_codes:
        mask &= transactions["status"].isin(status_codes).fillna(False)
    if status_classes:
        class_mask = pd.Series(False, index=transactions.index)
        for status_class in status_classes:
            if status_class == "No response":
                class_mask |= transactions["status"].isna()
            else:
                low = int(status_class[0]) * 100
                class_mask |= transactions["status"].between(low, low + 99).fillna(False)
        mask &= class_mask
    if ip.strip():
        needle = ip.strip()
        mask &= (transactions["client_ip"].str.contains(needle, regex=False)
                 | transactions["server_ip"].str.contains(needle, regex=False))
    if port is not None:
        mask &= _contains_port(transactions, ("client_port", "server_port"), port)
    if response_time_ms is not None:
        mask &= transactions["response_time_ms"].between(*response_time_ms).fillna(False)
    if states:
        mask &= transactions["state"].isin(states)
    if search.strip():
        needle = search.strip().lower()
        text = (transactions["host"] + transactions["uri"] + " " + transactions["id"]).str.lower()
        mask &= text.str.contains(needle, regex=False)
    return transactions[mask]


# --------------------------------------------------------------------------
# Insights
# --------------------------------------------------------------------------
@dataclass
class Insight:
    """One evidence-backed observation about the capture."""

    severity: str                 # "critical", "warning", "info" or "good"
    category: str                 # "performance", "errors", "completeness", "tcp", "security", "traffic"
    title: str
    detail: str
    frames: list[int] = field(default_factory=list)
    transaction_ids: list[str] = field(default_factory=list)
    stream_ids: list[int] = field(default_factory=list)


def build_insights(analysis: CaptureAnalysis, slow_threshold_seconds: float = 0.5) -> list[Insight]:
    """Derive observations from the analysis. Each one lists its evidence."""
    insights: list[Insight] = []
    transactions = analysis.transactions
    timed = [t for t in transactions if t.response_time is not None]

    # ---- performance ------------------------------------------------------
    slow = sorted((t for t in timed if t.response_time >= slow_threshold_seconds),
                  key=lambda t: t.response_time, reverse=True)
    if slow:
        worst = slow[0]
        insights.append(Insight(
            "warning", "performance", f"{len(slow)} slow HTTP transaction(s)",
            f"{len(slow)} of {len(timed)} timed transactions took at least {slow_threshold_seconds * 1000:.0f} ms. "
            f"Slowest: {worst.transaction_id} {worst.method} {worst.host}{worst.uri} "
            f"→ {worst.response_time * 1000:.1f} ms (request frame {worst.request_frame}, "
            f"response frame {worst.response_frame}).",
            frames=[f for t in slow for f in (t.request_frame, t.response_frame)],
            transaction_ids=[t.transaction_id for t in slow],
        ))
    elif timed:
        insights.append(Insight(
            "good", "performance", "No slow HTTP transactions",
            f"All {len(timed)} timed transactions completed in under {slow_threshold_seconds * 1000:.0f} ms.",
        ))

    # ---- HTTP errors --------------------------------------------------------
    for label, low, severity in (("server error (5xx)", 500, "critical"), ("client error (4xx)", 400, "warning")):
        matching = [t for t in transactions if t.status_code is not None and low <= t.status_code < low + 100]
        if matching:
            codes = sorted({t.status_code for t in matching})
            insights.append(Insight(
                severity, "errors", f"{len(matching)} HTTP {label} response(s)",
                "Status codes seen: " + ", ".join(str(code) for code in codes) + ". Examples: "
                + "; ".join(f"{t.transaction_id} {t.method} {t.host}{t.uri} → {t.status_code}" for t in matching[:3]) + ".",
                frames=[t.response_frame for t in matching],
                transaction_ids=[t.transaction_id for t in matching],
            ))

    # ---- completeness -------------------------------------------------------
    unanswered = [t for t in transactions if t.request is not None and t.response is None]
    if unanswered:
        insights.append(Insight(
            "warning", "completeness", f"{len(unanswered)} HTTP request(s) without a response",
            "No response was found in the capture for: "
            + "; ".join(f"{t.transaction_id} {t.method} {t.host}{t.uri} (frame {t.request_frame})" for t in unanswered[:5])
            + ("..." if len(unanswered) > 5 else "."),
            frames=[t.request_frame for t in unanswered],
            transaction_ids=[t.transaction_id for t in unanswered],
        ))
    orphans = [t for t in transactions if t.request is None]
    if orphans:
        insights.append(Insight(
            "info", "completeness", f"{len(orphans)} HTTP response(s) without a captured request",
            "These responses answer requests that are not in the capture, so no response time exists for them.",
            frames=[t.response_first_frame for t in orphans],
            transaction_ids=[t.transaction_id for t in orphans],
        ))
    uncertain = [t for t in transactions if t.match_confidence == "uncertain"]
    if uncertain:
        insights.append(Insight(
            "warning", "completeness", f"{len(uncertain)} uncertain request/response match(es)",
            "Bytes are missing from these TCP streams, so the pairing could not be proven. Verify them manually.",
            transaction_ids=[t.transaction_id for t in uncertain],
            stream_ids=sorted({t.stream_id for t in uncertain}),
        ))
    cut_off = [t for t in transactions if t.request and t.response and not t.is_complete]
    if cut_off:
        insights.append(Insight(
            "info", "completeness", f"{len(cut_off)} HTTP message(s) only partly captured",
            "The request or response body is shorter than announced, or its end could not be confirmed.",
            transaction_ids=[t.transaction_id for t in cut_off],
        ))

    # ---- TCP health ---------------------------------------------------------
    gap_streams = [s for s in analysis.streams if s.has_gaps]
    if gap_streams:
        missing = sum(s.client.gap_bytes + s.server.gap_bytes for s in gap_streams)
        insights.append(Insight(
            "warning", "tcp", f"{len(gap_streams)} TCP stream(s) with missing bytes",
            f"{missing:,} bytes that were acknowledged on the wire are absent from the capture "
            "(packet loss at the capture point or a limited snap length).",
            stream_ids=[s.stream_id for s in gap_streams],
        ))
    mid_streams = [s for s in analysis.streams if s.client.starts_mid_stream or s.server.starts_mid_stream]
    if mid_streams:
        insights.append(Insight(
            "info", "tcp", f"{len(mid_streams)} TCP stream(s) without a captured handshake",
            "The capture started after these connections were opened, so their beginning is unknown.",
            stream_ids=[s.stream_id for s in mid_streams],
        ))
    reset_streams = [s for s in analysis.streams if s.client.rst_frame or s.server.rst_frame]
    if reset_streams:
        insights.append(Insight(
            "warning", "tcp", f"{len(reset_streams)} TCP connection(s) ended with a reset (RST)",
            "A reset aborts a connection immediately instead of closing it gracefully.",
            frames=[s.client.rst_frame or s.server.rst_frame for s in reset_streams],
            stream_ids=[s.stream_id for s in reset_streams],
        ))
    retransmitted = [f for s in analysis.streams for d in (s.client, s.server) for f in d.retransmitted_frames]
    out_of_order = [f for s in analysis.streams for d in (s.client, s.server) for f in d.out_of_order_frames]
    if retransmitted or out_of_order:
        insights.append(Insight(
            "info", "tcp", f"{len(retransmitted)} retransmitted and {len(out_of_order)} out-of-order TCP segment(s)",
            "Duplicate data was ignored and out-of-order data was put back in sequence before HTTP parsing.",
            frames=sorted(retransmitted + out_of_order),
        ))

    # ---- security / visibility ---------------------------------------------
    exposed = [t for t in transactions if t.request and (
        t.request.header("Authorization") or t.request.header("Cookie") or t.request.header("Proxy-Authorization"))]
    if exposed:
        insights.append(Insight(
            "warning", "security", f"{len(exposed)} unencrypted request(s) carry credentials or cookies",
            "Authorization / Cookie headers were sent over plain HTTP, readable by anyone on the path. "
            "(Their values are masked in this dashboard and never sent to the AI service.)",
            frames=[t.request_frame for t in exposed],
            transaction_ids=[t.transaction_id for t in exposed],
        ))
    if analysis.tls_sessions:
        names = sorted({s.server_name for s in analysis.tls_sessions if s.server_name})
        insights.append(Insight(
            "info", "security", f"{len(analysis.tls_sessions)} encrypted TLS/HTTPS connection(s)",
            "Their HTTP content is encrypted and cannot be reconstructed; only handshake metadata is shown"
            + (": " + ", ".join(names[:6]) + ("..." if len(names) > 6 else "") if names else "") + ".",
            frames=[s.client_hello_frame for s in analysis.tls_sessions if s.client_hello_frame],
            stream_ids=[s.stream_id for s in analysis.tls_sessions],
        ))

    # ---- traffic ------------------------------------------------------------
    dns_failures = [p.frame for p in analysis.packets if p.protocol in ("DNS", "mDNS") and "No such name" in p.info]
    if dns_failures:
        insights.append(Insight(
            "warning", "traffic", f"{len(dns_failures)} failed DNS lookup(s)",
            "A DNS server answered 'No such name' (NXDOMAIN).", frames=dns_failures,
        ))
    unidentified = [p for p in analysis.packets if p.identification in (ID_TRANSPORT, ID_UNKNOWN, ID_PORT)]
    if unidentified and analysis.packets:
        share = len(unidentified) / len(analysis.packets)
        insights.append(Insight(
            "info", "traffic", f"{share:.0%} of packets have no verified application protocol",
            f"{len(unidentified):,} packets are plain TCP/UDP segments (for example ACKs), port-based guesses "
            "or unsupported traffic. They are counted but not interpreted.",
        ))
    for insight in insights:
        insight.frames = [frame for frame in insight.frames if frame]
    return insights


def response_time_statistics(transactions: pd.DataFrame) -> dict:
    """Summary statistics of HTTP response times in milliseconds."""
    times = transactions["response_time_ms"].dropna()
    if times.empty:
        return {"count": 0}
    return {
        "count": int(times.count()), "min": float(times.min()), "median": float(times.median()),
        "mean": float(times.mean()), "p95": float(times.quantile(0.95)), "max": float(times.max()),
    }
