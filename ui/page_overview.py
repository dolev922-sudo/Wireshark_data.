"""Overview page: capture summary, KPIs, protocol mix, traffic over time, endpoints."""

from __future__ import annotations

import streamlit as st

from analyzer import analytics

from . import charts, theme
from .state import Bundle


def render(bundle: Bundle) -> None:
    summary, analysis = bundle.summary, bundle.analysis
    theme.page_header("Overview", f"{summary['file_name']} · {summary['file_format'].upper()} · "
                                  f"{theme.format_bytes(summary['file_size'])}")
    for warning in analysis.warnings:
        st.warning(warning, icon=":material/warning:")
    if analysis.packet_count == 0:
        st.info("This capture contains no packets, so there is nothing to analyse.", icon=":material/info:")
        return

    answered = int(bundle.transactions["response_time_ms"].notna().sum())
    theme.kpi_row([
        ("Total packets", f"{summary['packet_count']:,}", f"{theme.format_bytes(summary['total_bytes'])} on the wire"),
        ("Capture duration", theme.format_duration(summary["duration"]),
         f"{summary['packets_per_second']:,.1f} packets/s" if summary["packets_per_second"] else "single instant"),
        ("HTTP transactions", f"{summary['http_transactions']:,}",
         f"{answered:,} answered · {summary['http_transactions'] - answered:,} without a matched pair"),
        ("Unique IP addresses", f"{summary['unique_ips']:,}", f"{summary['tcp_streams']:,} TCP streams"),
        ("Encrypted sessions", f"{summary['tls_sessions']:,}", "TLS/HTTPS · metadata only"),
    ])

    left, right = st.columns([3, 2], gap="large")
    with left:
        theme.section("Traffic over time")
        measure = st.segmented_control("Measure", ["Packets", "Bytes"], default="Packets", key="ov_time_measure",
                                       label_visibility="collapsed") or "Packets"
        series, bin_size = analytics.traffic_over_time(bundle.packets)
        st.plotly_chart(charts.traffic_over_time(series, bin_size, measure.lower()), config=charts.PLOT_CONFIG,
                        key="ov_time_chart")
    with right:
        theme.section("Protocol distribution")
        proto_measure = st.segmented_control("Measure ", ["Packets", "Bytes"], default="Packets",
                                             key="ov_proto_measure", label_visibility="collapsed") or "Packets"
        distribution = analytics.protocol_distribution(bundle.packets)
        st.plotly_chart(charts.protocol_bars(distribution, proto_measure.lower()), config=charts.PLOT_CONFIG,
                        key="ov_proto_chart")

    with st.expander("Protocol table and how each protocol was identified"):
        st.caption("“Verified from payload” means the bytes were inspected. “Guessed from port” is only a "
                   "well-known port number. “Transport only” packets (for example bare TCP ACKs) carry no "
                   "identified application data. The HTTP row counts the frames that complete an HTTP message, "
                   "like Wireshark’s Protocol column.")
        st.dataframe(distribution, hide_index=True, column_config={
            "protocol": "Protocol", "packets": st.column_config.NumberColumn("Packets", format="localized"),
            "bytes": st.column_config.NumberColumn("Bytes", format="localized"),
            "packet_share": st.column_config.NumberColumn("Share of packets", format="percent"),
            "identification": "How identified"})

    left, right = st.columns([3, 2], gap="large")
    with left:
        theme.section("Main network endpoints")
        if bundle.endpoints.empty:
            st.info("No IP traffic in this capture.")
        else:
            st.plotly_chart(charts.endpoint_bars(bundle.endpoints), config=charts.PLOT_CONFIG, key="ov_endpoints")
    with right:
        theme.section("Capture summary")
        theme.key_values([
            ("First packet", theme.format_timestamp(summary["start_time"])),
            ("Last packet", theme.format_timestamp(summary["end_time"])),
            ("Duration", f"{summary['duration']:.6f} s"),
            ("Average packet", f"{summary['average_packet_size']:,.1f} bytes"),
            ("Average rate", f"{summary['bits_per_second'] / 1000:,.1f} kbit/s" if summary["bits_per_second"] else "-"),
            ("File format", summary["file_format"].upper()),
            ("SHA-256", summary["sha256"][:32] + "…"),
        ])

    with st.expander("All endpoints and conversations"):
        tab_endpoints, tab_pairs = st.tabs(["IP endpoints", "IP conversations"])
        number = lambda label: st.column_config.NumberColumn(label, format="localized")   # noqa: E731
        tab_endpoints.dataframe(bundle.endpoints, hide_index=True, column_config={
            "ip": "IP address", "packets_sent": number("Packets sent"), "packets_received": number("Packets received"),
            "bytes_sent": number("Bytes sent"), "bytes_received": number("Bytes received"),
            "total_packets": number("Total packets"), "total_bytes": number("Total bytes")})
        tab_pairs.dataframe(analytics.conversations(bundle.packets), hide_index=True, column_config={
            "address_a": "Address A", "address_b": "Address B", "packets": number("Packets"), "bytes": number("Bytes")})
