"""Plotly figures with one shared visual style.

Rules followed in every chart: one y-axis, thin marks, recessive grid, colour
only where it encodes something (categorical colours in a fixed order, status
colours only for status), and a hover tooltip on every mark.
"""

from __future__ import annotations

import pandas as pd
import plotly.graph_objects as go

from .theme import ACCENT_ALT, BORDER, GRID, SERIES, STATUS, SURFACE, TEXT, TEXT_MUTED, TEXT_SECONDARY, format_bytes

FONT = "Inter, 'Segoe UI', system-ui, sans-serif"
PLOT_CONFIG = {"displayModeBar": False, "responsive": True}
STATUS_CLASS_COLORS = {"2xx Success": STATUS["good"], "3xx Redirect": STATUS["info"],
                       "4xx Client error": STATUS["warning"], "5xx Server error": STATUS["critical"],
                       "1xx Informational": STATUS["neutral"]}


def _style(figure: go.Figure, height: int = 300, legend: bool = False) -> go.Figure:
    figure.update_layout(
        height=height, margin=dict(l=8, r=16, t=12, b=8),
        paper_bgcolor="rgba(0,0,0,0)", plot_bgcolor="rgba(0,0,0,0)",
        font=dict(family=FONT, color=TEXT_SECONDARY, size=12),
        showlegend=legend,
        legend=dict(orientation="h", yanchor="bottom", y=1.02, xanchor="left", x=0, font=dict(color=TEXT_SECONDARY)),
        hoverlabel=dict(bgcolor=SURFACE, bordercolor=BORDER, font=dict(family=FONT, color=TEXT, size=12)),
        bargap=0.35,
    )
    figure.update_xaxes(gridcolor=GRID, zeroline=False, linecolor=BORDER, tickfont=dict(color=TEXT_MUTED),
                        title_font=dict(color=TEXT_MUTED, size=11))
    figure.update_yaxes(gridcolor=GRID, zeroline=False, linecolor=BORDER, tickfont=dict(color=TEXT_MUTED),
                        title_font=dict(color=TEXT_MUTED, size=11))
    return figure


def status_class(status) -> str:
    if status is None or pd.isna(status):
        return "No response"
    return {1: "1xx Informational", 2: "2xx Success", 3: "3xx Redirect", 4: "4xx Client error",
            5: "5xx Server error"}.get(int(status) // 100, "Other")


def traffic_over_time(series: pd.DataFrame, bin_size: float, measure: str) -> go.Figure:
    """Area chart of packets (or bytes) per time bucket."""
    values = series[measure]
    unit = "packets" if measure == "packets" else "bytes"
    bucket = f"{bin_size * 1000:g} ms" if bin_size < 1 else f"{bin_size:g} s"
    figure = go.Figure(go.Scatter(
        x=series["time"], y=values, mode="lines", line=dict(color=ACCENT_ALT, width=2, shape="hv"),
        fill="tozeroy", fillcolor="rgba(34,211,238,0.12)",
        customdata=[format_bytes(v) if measure == "bytes" else f"{int(v):,} packets" for v in values],
        hovertemplate="t = %{x:.3f} s<br>%{customdata} in this " + bucket + " bucket<extra></extra>",
    ))
    figure.update_xaxes(title_text=f"Seconds since first packet (bucket = {bucket})")
    figure.update_yaxes(title_text=f"{unit.capitalize()} per bucket", rangemode="tozero")
    return _style(figure, height=290)


def protocol_bars(distribution: pd.DataFrame, measure: str) -> go.Figure:
    """Horizontal bars, largest first. One hue: the bars differ by length, not colour."""
    data = distribution.sort_values(measure, ascending=True)
    total = data[measure].sum() or 1
    labels = [f"{value / total:.1%}" for value in data[measure]]
    hover = [f"{format_bytes(row.bytes)} in {int(row.packets):,} packets<br>{row.identification}"
             for row in data.itertuples()]
    figure = go.Figure(go.Bar(
        x=data[measure], y=data["protocol"], orientation="h", marker=dict(color=ACCENT_ALT, cornerradius=4),
        text=labels, textposition="outside", textfont=dict(color=TEXT_SECONDARY, size=11), cliponaxis=False,
        customdata=hover, hovertemplate="<b>%{y}</b><br>%{customdata}<extra></extra>",
    ))
    figure.update_xaxes(title_text="Packets" if measure == "packets" else "Bytes", showgrid=True)
    figure.update_yaxes(showgrid=False, tickfont=dict(color=TEXT_SECONDARY))
    figure.update_layout(bargap=0.4)
    return _style(figure, height=max(220, 34 * len(data) + 70))


def endpoint_bars(endpoints: pd.DataFrame, top: int = 8) -> go.Figure:
    """Bytes sent and received by the busiest IP addresses (two labelled series)."""
    data = endpoints.head(top).iloc[::-1]
    figure = go.Figure()
    for column, name, color in (("bytes_sent", "Sent", SERIES[0]), ("bytes_received", "Received", SERIES[1])):
        figure.add_trace(go.Bar(
            x=data[column], y=data["ip"], name=name, orientation="h",
            marker=dict(color=color, cornerradius=4, line=dict(color=SURFACE, width=1)),
            customdata=[format_bytes(v) for v in data[column]],
            hovertemplate="<b>%{y}</b><br>" + name + ": %{customdata}<extra></extra>",
        ))
    figure.update_layout(barmode="group", bargap=0.3, bargroupgap=0.08)
    figure.update_xaxes(title_text="Bytes")
    figure.update_yaxes(showgrid=False, tickfont=dict(color=TEXT_SECONDARY))
    return _style(figure, height=max(240, 44 * len(data) + 80), legend=True)


def response_times(transactions: pd.DataFrame, threshold_ms: float) -> go.Figure:
    """One bar per answered transaction, coloured by status class, with the slow threshold marked."""
    data = transactions.dropna(subset=["response_time_ms"]).copy()
    data["class"] = data["status"].map(status_class)
    figure = go.Figure()
    for name, color in STATUS_CLASS_COLORS.items():
        subset = data[data["class"] == name]
        if subset.empty:
            continue
        figure.add_trace(go.Bar(
            x=subset["id"], y=subset["response_time_ms"], name=name,
            marker=dict(color=color, cornerradius=4),
            customdata=list(zip(subset["method"], subset["host"] + subset["uri"].str.slice(0, 60), subset["status"],
                                subset["request_frame"], subset["response_frame"])),
            hovertemplate=("<b>%{x}</b> %{customdata[0]} %{customdata[1]}<br>Status %{customdata[2]}"
                           "<br>%{y:,.1f} ms (frames %{customdata[3]} → %{customdata[4]})<extra></extra>"),
        ))
    figure.add_hline(y=threshold_ms, line=dict(color=TEXT_MUTED, width=1, dash="dash"),
                     annotation_text=f"slow threshold {threshold_ms:,.0f} ms", annotation_position="top left",
                     annotation_font=dict(color=TEXT_MUTED, size=11))
    figure.update_xaxes(title_text="Transaction", categoryorder="array", categoryarray=list(data["id"]), showgrid=False)
    figure.update_yaxes(title_text="Response time (ms)", rangemode="tozero")
    return _style(figure, height=320, legend=True)


def status_code_bars(transactions: pd.DataFrame) -> go.Figure:
    data = transactions.copy()
    data["label"] = data["status"].map(lambda value: "No response" if pd.isna(value) else str(int(value)))
    data["class"] = data["status"].map(status_class)
    counts = data.groupby(["label", "class"]).size().reset_index(name="count").sort_values("label")
    colors = [STATUS_CLASS_COLORS.get(name, STATUS["neutral"]) for name in counts["class"]]
    figure = go.Figure(go.Bar(
        x=counts["label"], y=counts["count"], marker=dict(color=colors, cornerradius=4),
        text=counts["count"], textposition="outside", textfont=dict(color=TEXT_SECONDARY), cliponaxis=False,
        customdata=counts["class"], hovertemplate="<b>%{x}</b> (%{customdata})<br>%{y} transaction(s)<extra></extra>",
    ))
    figure.update_xaxes(title_text="HTTP status code", type="category", showgrid=False)
    figure.update_yaxes(title_text="Transactions", rangemode="tozero", dtick=max(1, int(counts["count"].max() // 5) or 1))
    return _style(figure, height=280)


def transaction_timeline(request_at: float, first_byte_at: float, complete_at: float) -> go.Figure:
    """Where the time of one transaction went: waiting for the first byte vs receiving the response."""
    waiting, receiving = (first_byte_at - request_at) * 1000, (complete_at - first_byte_at) * 1000
    figure = go.Figure()
    figure.add_trace(go.Bar(
        x=[waiting], y=["Timeline"], base=[0], orientation="h", name="Waiting for first byte",
        marker=dict(color=SERIES[0], cornerradius=4), hovertemplate="Waiting for first byte: %{x:,.3f} ms<extra></extra>"))
    figure.add_trace(go.Bar(
        x=[receiving], y=["Timeline"], base=[waiting], orientation="h", name="Receiving response",
        marker=dict(color=SERIES[1], cornerradius=4, line=dict(color=SURFACE, width=2)),
        hovertemplate="Receiving response: %{x:,.3f} ms<extra></extra>"))
    figure.update_layout(barmode="overlay")
    figure.update_xaxes(title_text="Milliseconds after the request frame", rangemode="tozero")
    figure.update_yaxes(showticklabels=False, showgrid=False)
    return _style(figure, height=150, legend=True)
