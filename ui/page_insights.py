"""Insights page: evidence-backed findings, HTTP performance, TCP health and investigation filters."""

from __future__ import annotations

import pandas as pd
import streamlit as st

from analyzer import analytics

from . import charts, theme
from .page_http import TABLE_ORDER, TRANSACTION_COLUMNS
from .state import Bundle, get_settings, go_to, parse_port, slow_threshold_seconds

CATEGORY_LABELS = {"performance": "Performance", "errors": "HTTP errors", "completeness": "Completeness",
                   "tcp": "TCP health", "security": "Security & privacy", "traffic": "Traffic"}
SEVERITY_LABELS = {"critical": "Critical", "warning": "Warning", "info": "Note", "good": "OK"}


def render(bundle: Bundle) -> None:
    theme.page_header("Insights", "Findings computed from the capture. Every finding lists the frames or transactions behind it.")
    if bundle.analysis.packet_count == 0:
        st.info("This capture contains no packets.", icon=":material/info:")
        return
    tab_findings, tab_performance, tab_tcp, tab_filters = st.tabs(
        ["Findings", "HTTP performance", "TCP streams", "Investigation filters"])
    with tab_findings:
        render_findings(bundle)
    with tab_performance:
        render_performance(bundle)
    with tab_tcp:
        render_tcp(bundle)
    with tab_filters:
        render_investigation(bundle)


def render_findings(bundle: Bundle) -> None:
    insights = analytics.build_insights(bundle.analysis, slow_threshold_seconds())
    if not insights:
        st.info("Nothing noteworthy was detected.")
        return
    counts = {level: sum(1 for i in insights if i.severity == level) for level in SEVERITY_LABELS}
    st.markdown(" ".join(theme.badge(f"{counts[level]} {SEVERITY_LABELS[level]}", level)
                         for level in SEVERITY_LABELS if counts[level]), unsafe_allow_html=True)
    chosen = st.pills("Category", [CATEGORY_LABELS[c] for c in CATEGORY_LABELS if any(i.category == c for i in insights)],
                      selection_mode="multi", key="ins_categories", label_visibility="collapsed")
    order = {"critical": 0, "warning": 1, "info": 2, "good": 3}
    for insight in sorted(insights, key=lambda i: order[i.severity]):
        if chosen and CATEGORY_LABELS[insight.category] not in chosen:
            continue
        evidence = []
        if insight.transaction_ids:
            evidence.append("Transactions: " + ", ".join(insight.transaction_ids[:10])
                            + ("…" if len(insight.transaction_ids) > 10 else ""))
        if insight.frames:
            evidence.append("Frames: " + ", ".join(str(f) for f in insight.frames[:14])
                            + ("…" if len(insight.frames) > 14 else ""))
        if insight.stream_ids:
            evidence.append("TCP streams: " + ", ".join(str(s) for s in insight.stream_ids[:14]))
        theme.card(insight.title, insight.detail, " · ".join(evidence), tone=insight.severity,
                   badges=theme.badge(f"{SEVERITY_LABELS[insight.severity]} · {CATEGORY_LABELS[insight.category]}",
                                      insight.severity))


def render_performance(bundle: Bundle) -> None:
    transactions = bundle.transactions
    if transactions.empty:
        st.info("No unencrypted HTTP transactions were found, so there is no HTTP performance data.", icon=":material/info:")
        return
    default_ms = int(get_settings().slow_threshold_seconds * 1000)
    threshold = st.slider("Slow-request threshold (ms)", 10, 5000, default_ms, step=10, key="slow_threshold_ms",
                          help="A transaction is 'slow' when its response time is at least this long.")
    slow = transactions[transactions["response_time_ms"] >= threshold].sort_values("response_time_ms", ascending=False)
    errors = transactions[transactions["status"] >= 400]
    incomplete = transactions[transactions["state"] != "Complete"]
    theme.kpi_row([
        ("Slow transactions", f"{len(slow):,}", f"response time ≥ {threshold:,} ms"),
        ("HTTP errors", f"{len(errors):,}", f"{int((errors['status'] >= 500).sum())} server · "
                                            f"{int((errors['status'] < 500).sum())} client"),
        ("Incomplete exchanges", f"{len(incomplete):,}", "no response, cut off or uncertain"),
    ])
    left, right = st.columns([3, 2], gap="large")
    with left:
        theme.section("Response time per transaction")
        if transactions["response_time_ms"].notna().any():
            st.plotly_chart(charts.response_times(transactions, threshold), config=charts.PLOT_CONFIG, key="ins_rt")
        else:
            st.info("No transaction has both a request and a response.")
    with right:
        theme.section("Status codes")
        st.plotly_chart(charts.status_code_bars(transactions), config=charts.PLOT_CONFIG, key="ins_status")

    for title, table, empty in (
        (f"Slow transactions (≥ {threshold:,} ms)", slow, "No transaction reached the threshold."),
        ("HTTP error responses (4xx / 5xx)", errors, "No error status codes were found."),
        ("Incomplete or uncertain exchanges", incomplete, "Every request has a complete, confirmed response."),
    ):
        theme.section(title)
        if table.empty:
            st.success(empty, icon=":material/check_circle:")
        else:
            columns = TABLE_ORDER[:12] + (["warnings"] if title.startswith("Incomplete") else [])
            st.dataframe(table[columns], hide_index=True,
                         column_config={**TRANSACTION_COLUMNS, "warnings": st.column_config.TextColumn("Why", width="large")})

    with st.expander("How this helps you read a capture"):
        st.markdown(
            "- **Slow transactions** point at where a user actually waited. Comparing *first byte* with *response time* "
            "separates a slow server (long wait for the first byte) from a slow transfer (long download).\n"
            "- **Error status codes** show which requests the server refused (4xx) or failed to handle (5xx).\n"
            "- **Incomplete exchanges** stop you from trusting numbers that do not exist: a request without a captured "
            "response has no response time, and a pairing made across missing bytes is flagged instead of presented as fact.")


def render_tcp(bundle: Bundle) -> None:
    streams = bundle.streams
    if streams.empty:
        st.info("No TCP traffic in this capture.", icon=":material/info:")
        return
    with_issues = streams[streams["issues"] != ""]
    theme.kpi_row([
        ("TCP streams", f"{len(streams):,}", f"{int((streams['application'] == 'HTTP').sum())} HTTP · "
                                             f"{int((streams['application'] == 'TLS').sum())} TLS"),
        ("Streams with issues", f"{len(with_issues):,}", "missing handshake, gaps, reset or no close"),
        ("Missing bytes", f"{int(streams['missing_bytes'].sum()):,}", "acknowledged data absent from the capture"),
        ("Retransmissions", f"{int(streams['retransmissions'].sum()):,}", f"{int(streams['out_of_order'].sum())} out-of-order segments"),
    ])
    only_issues = st.toggle("Show only streams with issues", key="ins_tcp_only")
    shown = with_issues if only_issues else streams
    st.markdown("Select a stream to open its packets in the Packet Explorer.")
    event = st.dataframe(
        shown[["stream", "client", "server", "application", "packets", "bytes", "duration", "handshake",
               "missing_bytes", "retransmissions", "out_of_order", "issues"]],
        hide_index=True, on_select="rerun", selection_mode="single-row", key="ins_tcp_table",
        column_config={
            "stream": st.column_config.NumberColumn("TCP stream", format="%d", width="small"),
            "client": "Client", "server": "Server", "application": "Application",
            "packets": st.column_config.NumberColumn("Packets", format="localized"),
            "bytes": st.column_config.NumberColumn("Payload bytes", format="localized"),
            "duration": st.column_config.NumberColumn("Duration (s)", format="%.3f"),
            "handshake": st.column_config.CheckboxColumn("Full handshake"),
            "missing_bytes": st.column_config.NumberColumn("Missing bytes", format="localized"),
            "retransmissions": "Retransmissions", "out_of_order": "Out of order",
            "issues": st.column_config.TextColumn("Issues", width="large")})
    rows = event.selection.rows if event and event.selection else []
    if rows and rows[0] < len(shown):
        stream_id = int(shown.iloc[rows[0]]["stream"])
        if st.button(f"Open TCP stream {stream_id} in Packet Explorer", icon=":material/table_rows:", key="ins_open_stream"):
            go_to("packets", px_stream=str(stream_id), px_search="", px_ip="", px_port="", px_protocols=[], px_issues=False)


def render_investigation(bundle: Bundle) -> None:
    """One set of filters applied to both the packet list and the HTTP transactions."""
    packets, transactions = bundle.packets, bundle.transactions
    st.caption("Combine filters to isolate the traffic you are investigating. Protocol, IP and port narrow the packet "
               "list; host, method, status and response time narrow the HTTP transactions, and the packet list then "
               "keeps only the frames of the matching transactions.")
    with st.container(border=True):
        row1 = st.columns(4)
        protocols = row1[0].multiselect("Protocol", sorted(packets["protocol"].unique()), key="inv_protocols")
        ip = row1[1].text_input("IP address", key="inv_ip", placeholder="e.g. 192.168.1.20")
        port_text = row1[2].text_input("Port", key="inv_port", placeholder="e.g. 8080")
        hosts = row1[3].multiselect("HTTP host", sorted(h for h in transactions["host"].unique() if h), key="inv_hosts")
        row2 = st.columns(4)
        methods = row2[0].multiselect("HTTP method", sorted(m for m in transactions["method"].unique() if m), key="inv_methods")
        codes = sorted(int(c) for c in transactions["status"].dropna().unique())
        status_codes = row2[1].multiselect("Status code", codes, key="inv_codes")
        classes = row2[2].multiselect("Status class", ["2xx", "3xx", "4xx", "5xx", "No response"], key="inv_classes")
        times = transactions["response_time_ms"].dropna()
        time_range = None
        if len(times) and times.max() > times.min():
            low, high = float(times.min()), float(times.max())
            chosen = row2[3].slider("Response time (ms)", low, high, (low, high), key="inv_rt", format="%.1f")
            if chosen != (low, high):
                time_range = chosen
    port, port_error = parse_port(port_text)
    if port_error:
        st.error(port_error)

    http_filter_active = bool(hosts or methods or status_codes or classes or time_range)
    matched_transactions = analytics.filter_transactions(
        transactions, methods=methods, hosts=hosts, status_codes=status_codes, status_classes=classes,
        ip=ip, port=port, response_time_ms=time_range)
    matched_packets = analytics.filter_packets(packets, protocols=protocols, ip=ip, port=port)
    if http_filter_active:
        frames: set[int] = set()
        for transaction_id in matched_transactions["id"]:
            transaction = bundle.analysis.transaction(transaction_id)
            for message in (transaction.request, transaction.response, *transaction.informational):
                if message:
                    frames.update(message.frames)
        matched_packets = matched_packets[matched_packets["frame"].isin(frames)]

    theme.kpi_row([
        ("Matching packets", f"{len(matched_packets):,}", f"of {len(packets):,}"),
        ("Matching bytes", theme.format_bytes(matched_packets["length"].sum()), "on the wire"),
        ("Matching HTTP transactions", f"{len(matched_transactions):,}", f"of {len(transactions):,}"),
        ("Median response time", theme.format_ms(matched_transactions["response_time_ms"].median()
                                                 if matched_transactions["response_time_ms"].notna().any() else None),
         "of the matching transactions"),
    ])
    tab_http, tab_packets = st.tabs([f"HTTP transactions ({len(matched_transactions):,})", f"Packets ({len(matched_packets):,})"])
    tab_http.dataframe(matched_transactions[TABLE_ORDER], hide_index=True, column_config=TRANSACTION_COLUMNS)
    tab_packets.dataframe(
        matched_packets.head(20_000)[["frame", "time", "src_ip", "src_port", "dst_ip", "dst_port", "protocol", "length", "info"]],
        hide_index=True, column_config={
            "frame": st.column_config.NumberColumn("Frame", format="%d", width="small"),
            "time": st.column_config.NumberColumn("Time (s)", format="%.6f", width="small"),
            "src_ip": "Source", "src_port": st.column_config.NumberColumn("Src port", format="%d", width="small"),
            "dst_ip": "Destination", "dst_port": st.column_config.NumberColumn("Dst port", format="%d", width="small"),
            "protocol": "Protocol", "length": st.column_config.NumberColumn("Length", format="%d", width="small"),
            "info": st.column_config.TextColumn("Info", width="large")})
    if isinstance(matched_packets, pd.DataFrame) and len(matched_packets) > 20_000:
        tab_packets.caption("Only the first 20,000 matching packets are displayed.")
