"""Visual identity: colours, CSS, small HTML building blocks and formatters.

Custom HTML is limited to our own elements (cards, badges, headers) that we
fully control. All text that comes from a capture file is HTML-escaped first,
because a capture is untrusted input.
"""

from __future__ import annotations

import html
from datetime import datetime, timezone
from typing import Optional

import streamlit as st

# ---- colour roles -----------------------------------------------------------
BACKGROUND = "#0b1220"
SURFACE = "#111a2e"
SURFACE_RAISED = "#16213a"
BORDER = "#22304d"
TEXT = "#e6edf7"
TEXT_SECONDARY = "#a9b6cc"
TEXT_MUTED = "#7f8ea8"
ACCENT = "#2dd4bf"          # teal - brand / interactive
ACCENT_ALT = "#22d3ee"      # cyan - single-series charts
GRID = "#1c2942"

# Categorical series colours, always used in this fixed order (validated for
# colour-blind separation and contrast on SURFACE).
SERIES = ["#3987e5", "#d95926", "#199e70", "#c98500", "#d55181", "#9085e9"]

# Status colours are reserved for state and always shown together with a label.
STATUS = {"good": "#0ca30c", "info": "#3987e5", "warning": "#fab219", "serious": "#ec835a",
          "critical": "#d03b3b", "neutral": "#7f8ea8"}
STATUS_ICONS = {"good": "✓", "info": "ℹ", "warning": "⚠", "serious": "⚠", "critical": "✖",
                "neutral": "•"}

CSS = f"""
<style>
.block-container {{ padding-top: 2.2rem; padding-bottom: 3rem; max-width: 1500px; }}
h1, h2, h3 {{ letter-spacing: -0.01em; }}

.nta-brand {{ display:flex; align-items:center; gap:.65rem; margin:.2rem 0 1rem 0; }}
.nta-brand-mark {{ width:34px; height:34px; border-radius:9px; background:{ACCENT}; color:{BACKGROUND};
  display:flex; align-items:center; justify-content:center; font-weight:800; font-size:1rem; }}
.nta-brand-name {{ font-weight:700; font-size:1.02rem; color:{TEXT}; line-height:1.1; }}
.nta-brand-sub {{ font-size:.72rem; color:{TEXT_MUTED}; letter-spacing:.06em; text-transform:uppercase; }}

.nta-page-header {{ margin-bottom:1.1rem; }}
.nta-page-title {{ font-size:1.65rem; font-weight:700; color:{TEXT}; margin:0; }}
.nta-page-sub {{ color:{TEXT_SECONDARY}; font-size:.95rem; margin-top:.2rem; }}
.nta-section {{ font-size:.78rem; font-weight:600; letter-spacing:.09em; text-transform:uppercase;
  color:{TEXT_MUTED}; margin:1.4rem 0 .6rem 0; }}

.nta-kpi-grid {{ display:grid; grid-template-columns:repeat(auto-fit,minmax(170px,1fr)); gap:.8rem; }}
.nta-kpi {{ background:{SURFACE}; border:1px solid {BORDER}; border-radius:12px; padding:.95rem 1.05rem;
  border-top:2px solid {ACCENT}; min-width:0; }}
.nta-kpi-label {{ font-size:.74rem; letter-spacing:.07em; text-transform:uppercase; color:{TEXT_MUTED}; }}
.nta-kpi-value {{ font-size:1.7rem; font-weight:700; color:{TEXT}; line-height:1.25; margin-top:.15rem;
  font-variant-numeric:tabular-nums; overflow-wrap:anywhere; }}
.nta-kpi-note {{ font-size:.8rem; color:{TEXT_SECONDARY}; margin-top:.1rem; overflow-wrap:anywhere; }}

.nta-card {{ background:{SURFACE}; border:1px solid {BORDER}; border-radius:12px; padding:1rem 1.1rem;
  margin-bottom:.7rem; }}
.nta-card-title {{ font-weight:600; color:{TEXT}; font-size:.98rem; }}
.nta-card-body {{ color:{TEXT_SECONDARY}; font-size:.9rem; margin-top:.3rem; line-height:1.5; overflow-wrap:anywhere; }}
.nta-card-meta {{ color:{TEXT_MUTED}; font-size:.8rem; margin-top:.45rem; font-variant-numeric:tabular-nums; }}
.nta-insight {{ border-left:3px solid var(--tone); }}

.nta-badge {{ display:inline-flex; align-items:center; gap:.3rem; padding:.12rem .55rem; border-radius:999px;
  font-size:.74rem; font-weight:600; border:1px solid var(--tone); color:{TEXT}; white-space:nowrap;
  background:color-mix(in srgb, var(--tone) 16%, transparent); }}
.nta-badge-icon {{ color:var(--tone); }}

.nta-kv {{ display:grid; grid-template-columns:max-content 1fr; gap:.3rem 1.1rem; font-size:.9rem; }}
.nta-kv dt {{ color:{TEXT_MUTED}; }}
.nta-kv dd {{ color:{TEXT}; margin:0; overflow-wrap:anywhere; font-variant-numeric:tabular-nums; }}

.nta-steps {{ counter-reset:step; list-style:none; padding:0; margin:0; }}
.nta-steps li {{ counter-increment:step; position:relative; padding:.1rem 0 .75rem 2.3rem; color:{TEXT_SECONDARY};
  font-size:.9rem; line-height:1.5; overflow-wrap:anywhere; }}
.nta-steps li::before {{ content:counter(step); position:absolute; left:0; top:0; width:1.55rem; height:1.55rem;
  border-radius:50%; border:1px solid {ACCENT}; color:{ACCENT}; font-size:.78rem; font-weight:700;
  display:flex; align-items:center; justify-content:center; }}
.nta-steps b {{ color:{TEXT}; }}

.nta-hero {{ background:{SURFACE}; border:1px solid {BORDER}; border-radius:16px; padding:2.2rem 2.4rem; }}
.nta-hero h1 {{ font-size:2rem; margin:0 0 .5rem 0; color:{TEXT}; }}
.nta-hero p {{ color:{TEXT_SECONDARY}; font-size:1.02rem; max-width:62ch; margin:0; }}
.nta-feature-grid {{ display:grid; grid-template-columns:repeat(auto-fit,minmax(180px,1fr)); gap:.8rem; margin-top:1rem; }}

code, .nta-mono {{ font-family: ui-monospace, "Cascadia Code", Consolas, monospace; }}
/* Hebrew and English answers: each paragraph picks its own text direction. */
[data-testid="stChatMessage"] p, [data-testid="stChatMessage"] li {{ unicode-bidi: plaintext; text-align: start; }}
</style>
"""


def apply_theme() -> None:
    st.markdown(CSS, unsafe_allow_html=True)


# ---- HTML building blocks ---------------------------------------------------
def esc(value: object) -> str:
    """Escape untrusted text for safe inclusion in HTML."""
    return html.escape(str(value), quote=True)


def page_header(title: str, subtitle: str = "") -> None:
    st.markdown(
        f'<div class="nta-page-header"><div class="nta-page-title">{esc(title)}</div>'
        f'<div class="nta-page-sub">{esc(subtitle)}</div></div>', unsafe_allow_html=True)


def section(title: str) -> None:
    st.markdown(f'<div class="nta-section">{esc(title)}</div>', unsafe_allow_html=True)


def kpi_row(cards: list[tuple[str, str, str]]) -> None:
    """Render KPI cards. Each card is (label, value, note)."""
    blocks = "".join(
        f'<div class="nta-kpi"><div class="nta-kpi-label">{esc(label)}</div>'
        f'<div class="nta-kpi-value">{esc(value)}</div><div class="nta-kpi-note">{esc(note)}</div></div>'
        for label, value, note in cards)
    st.markdown(f'<div class="nta-kpi-grid">{blocks}</div>', unsafe_allow_html=True)


def badge(text: str, tone: str = "neutral") -> str:
    """Return badge HTML: status colour + icon + label (never colour alone)."""
    return (f'<span class="nta-badge" style="--tone:{STATUS.get(tone, STATUS["neutral"])}">'
            f'<span class="nta-badge-icon">{STATUS_ICONS.get(tone, "")}</span>{esc(text)}</span>')


def card(title: str, body: str = "", meta: str = "", tone: Optional[str] = None, badges: str = "") -> None:
    """A bordered card. ``badges`` must already be safe HTML produced by badge()."""
    style = f' style="--tone:{STATUS[tone]}"' if tone else ""
    classes = "nta-card nta-insight" if tone else "nta-card"
    parts = [f'<div class="nta-card-title">{badges}{" " if badges else ""}{esc(title)}</div>']
    if body:
        parts.append(f'<div class="nta-card-body">{esc(body)}</div>')
    if meta:
        parts.append(f'<div class="nta-card-meta">{esc(meta)}</div>')
    st.markdown(f'<div class="{classes}"{style}>{"".join(parts)}</div>', unsafe_allow_html=True)


def key_values(pairs: list[tuple[str, object]]) -> None:
    rows = "".join(f"<dt>{esc(key)}</dt><dd>{esc(value)}</dd>" for key, value in pairs)
    st.markdown(f'<dl class="nta-kv">{rows}</dl>', unsafe_allow_html=True)


def steps(items: list[str]) -> None:
    """Numbered explanation steps. Items must already be escaped (may contain <b>)."""
    st.markdown('<ol class="nta-steps">' + "".join(f"<li>{item}</li>" for item in items) + "</ol>",
                unsafe_allow_html=True)


# ---- formatters ---------------------------------------------------------------
def format_bytes(count: float) -> str:
    value = float(count)
    for unit in ("B", "KB", "MB", "GB"):
        if value < 1024 or unit == "GB":
            return f"{value:,.0f} {unit}" if unit == "B" else f"{value:,.1f} {unit}"
        value /= 1024
    return f"{value:,.1f} GB"


def format_duration(seconds: float) -> str:
    if seconds < 1:
        return f"{seconds * 1000:,.1f} ms"
    if seconds < 60:
        return f"{seconds:,.3f} s"
    minutes, rest = divmod(seconds, 60)
    if minutes < 60:
        return f"{int(minutes)} min {rest:,.1f} s"
    hours, minutes = divmod(int(minutes), 60)
    return f"{hours} h {minutes} min {rest:,.0f} s"


def format_timestamp(epoch: Optional[float]) -> str:
    """UTC wall-clock time with microseconds (Wireshark: View > Time Display Format > UTC)."""
    if epoch is None:
        return "-"
    return datetime.fromtimestamp(epoch, tz=timezone.utc).strftime("%Y-%m-%d %H:%M:%S.%f UTC")


def format_ms(value: Optional[float]) -> str:
    return "-" if value is None or value != value else f"{value:,.3f} ms"


def status_tone(status: Optional[int]) -> str:
    if status is None or status != status:
        return "neutral"
    if status >= 500:
        return "critical"
    if status >= 400:
        return "warning"
    if status >= 300:
        return "info"
    return "good"
