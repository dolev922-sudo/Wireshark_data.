"""Packet Explorer: searchable packet table and per-frame details."""

from __future__ import annotations

import scapy.layers.dns  # noqa: F401  (importing registers the protocol layers used for dissection)
import scapy.layers.inet  # noqa: F401
import scapy.layers.inet6  # noqa: F401
import scapy.layers.l2  # noqa: F401
import streamlit as st
from scapy.config import conf
from scapy.packet import Raw

from analyzer import analytics
from analyzer.analytics import IDENTIFICATION_LABELS
from analyzer.models import CaptureAnalysis

from . import theme
from .state import Bundle, parse_integer, parse_port

MAX_ROWS = 20_000


def hex_dump(data: bytes, limit: int = 2048) -> str:
    lines = []
    for offset in range(0, min(len(data), limit), 16):
        row = data[offset:offset + 16]
        hex_part = " ".join(f"{byte:02x}" for byte in row)
        text = "".join(chr(byte) if 32 <= byte < 127 else "." for byte in row)
        lines.append(f"{offset:04x}  {hex_part:<47}  {text}")
    if len(data) > limit:
        lines.append(f"... {len(data) - limit:,} more bytes not shown")
    return "\n".join(lines)


def dissect(analysis: CaptureAnalysis, frame: int) -> str:
    """Full layer-by-layer dissection of one frame, produced by Scapy on demand."""
    packet = analysis.packet(frame)
    raw = analysis.raw_frames[frame - 1]
    try:
        layer_class = conf.l2types.get(packet.link_type, Raw)
        return layer_class(raw).show(dump=True)
    except Exception as error:      # a malformed frame must not break the page
        return f"Scapy could not dissect this frame ({type(error).__name__}: {error})."


def render(bundle: Bundle) -> None:
    packets = bundle.packets
    theme.page_header("Packet Explorer", "Every captured frame, in file order. Frame numbers match Wireshark’s frame.number.")
    if packets.empty:
        st.info("This capture contains no packets.", icon=":material/info:")
        return

    with st.container(border=True):
        row1 = st.columns([3, 2, 2, 1.2, 1.2])
        search = row1[0].text_input("Search", key="px_search", placeholder="Text in info, IP or protocol…")
        protocols = row1[1].multiselect("Protocol", sorted(packets["protocol"].unique()), key="px_protocols")
        ip = row1[2].text_input("IP address (source or destination)", key="px_ip", placeholder="e.g. 192.168.1.20")
        port_text = row1[3].text_input("Port", key="px_port", placeholder="e.g. 80")
        stream_text = row1[4].text_input("TCP stream", key="px_stream", placeholder="e.g. 0")
        row2 = st.columns([2.2, 2.2, 1.6])
        last_frame = int(packets["frame"].max())
        frame_range = (1, last_frame)
        if last_frame > 1:
            frame_range = row2[0].slider("Frame number range", 1, last_frame, (1, last_frame), key="px_frames")
        duration = float(packets["time"].max())
        time_range = (0.0, duration)
        if duration > 0:
            time_range = row2[1].slider("Time range (seconds since first packet)", 0.0, duration, (0.0, duration),
                                        key="px_time", format="%.3f")
        only_issues = row2[2].toggle("Only TCP retransmissions / out-of-order", key="px_issues")

    port, port_error = parse_port(port_text)
    stream, stream_error = parse_integer(stream_text, "TCP stream")
    for message in (port_error, stream_error):
        if message:
            st.error(message)
    filtered = analytics.filter_packets(
        packets, protocols=protocols, ip=ip, port=port, search=search, stream=stream,
        frame_range=frame_range if frame_range != (1, last_frame) else None,
        time_range=time_range if time_range != (0.0, duration) else None, only_tcp_issues=only_issues)

    caption = f"Showing **{len(filtered):,}** of {len(packets):,} packets"
    shown = filtered
    if len(filtered) > MAX_ROWS:
        shown = filtered.head(MAX_ROWS)
        caption += f" — the table displays the first {MAX_ROWS:,}; narrow the filters to see the rest"
    st.markdown(caption + ". Select a row to inspect the frame.")

    event = st.dataframe(
        shown[["frame", "time", "src_ip", "src_port", "dst_ip", "dst_port", "protocol", "length", "info"]],
        hide_index=True, height=430, on_select="rerun", selection_mode="single-row", key="px_table",
        column_config={
            "frame": st.column_config.NumberColumn("Frame", format="%d", width="small"),
            "time": st.column_config.NumberColumn("Time (s)", format="%.6f", width="small"),
            "src_ip": "Source", "src_port": st.column_config.NumberColumn("Src port", format="%d", width="small"),
            "dst_ip": "Destination", "dst_port": st.column_config.NumberColumn("Dst port", format="%d", width="small"),
            "protocol": st.column_config.TextColumn("Protocol", width="small"),
            "length": st.column_config.NumberColumn("Length", format="%d", width="small"),
            "info": st.column_config.TextColumn("Info", width="large"),
        })
    st.download_button("Download filtered packets (CSV)", shown.drop(columns=["epoch"]).to_csv(index=False),
                       file_name="packets.csv", mime="text/csv", icon=":material/download:")

    selected_rows = event.selection.rows if event and event.selection else []
    if not selected_rows or selected_rows[0] >= len(shown):
        st.caption("No frame selected.")
        return
    render_frame_details(bundle, int(shown.iloc[selected_rows[0]]["frame"]))


def render_frame_details(bundle: Bundle, frame: int) -> None:
    analysis = bundle.analysis
    packet = analysis.packet(frame)
    theme.section(f"Frame {frame} details")
    left, right = st.columns([2, 3], gap="large")
    with left:
        pairs = [
            ("Frame number", frame),
            ("Timestamp", theme.format_timestamp(packet.timestamp)),
            ("Time since first packet", f"{packet.timestamp - analysis.start_time:.6f} s"),
            ("Length", f"{packet.wire_length} bytes on wire, {packet.captured_length} captured"),
            ("Protocol", f"{packet.protocol} — {IDENTIFICATION_LABELS[packet.identification]}"),
        ]
        if packet.src_mac:
            pairs.append(("MAC", f"{packet.src_mac} → {packet.dst_mac}"))
        if packet.src_ip:
            pairs.append((f"IPv{packet.ip_version}" if packet.ip_version else "Address",
                          f"{packet.src_ip} → {packet.dst_ip}" + (f" (TTL {packet.ttl})" if packet.ttl is not None else "")))
        if packet.src_port is not None:
            pairs.append((f"{packet.transport} ports", f"{packet.src_port} → {packet.dst_port}"))
        if packet.transport == "TCP" and packet.tcp_seq is not None:
            pairs += [("TCP flags", analytics.tcp_flags_text(packet.tcp_flags) or "none"),
                      ("Raw sequence / ack", f"{packet.tcp_seq} / {packet.tcp_ack}"),
                      ("TCP payload", f"{packet.payload_length} bytes"),
                      ("TCP stream", packet.stream_id)]
            if packet.tcp_analysis:
                pairs.append(("TCP analysis", packet.tcp_analysis))
        if packet.decode_error:
            pairs.append(("Decode problem", packet.decode_error))
        pairs.append(("Info", packet.info))
        theme.key_values(pairs)
        related = [t.transaction_id for t in analysis.transactions
                   if any(m and frame in m.frames for m in (t.request, t.response, *t.informational))]
        if related:
            st.caption("Part of HTTP transaction(s): " + ", ".join(related))
        st.caption(f"Wireshark display filter: `frame.number == {frame}`")
    with right:
        tab_layers, tab_hex = st.tabs(["Protocol layers (Scapy dissection)", "Hex dump"])
        tab_layers.code(dissect(analysis, frame), language=None, height=380)
        tab_hex.code(hex_dump(analysis.raw_frames[frame - 1]), language=None, height=380)
