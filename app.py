"""Network Traffic Analyzer Dashboard - Streamlit entry point.

Run with:   streamlit run app.py
"""

from __future__ import annotations

from pathlib import Path

import streamlit as st

from analyzer import CaptureError
from ui import page_ai, page_http, page_insights, page_overview, page_packets, theme
from ui.state import build_bundle, current_bundle, get_settings

SAMPLE_PATH = Path(__file__).parent / "samples" / "sample_http.pcap"

st.set_page_config(page_title="PacketScope · Network Traffic Analyzer", page_icon=":material/lan:",
                   layout="wide", initial_sidebar_state="expanded")
theme.apply_theme()


def load_capture(data: bytes, name: str, key: str) -> None:
    """Analyse a capture once and keep the result for the session."""
    if st.session_state.get("bundle_key") == key:
        return
    st.session_state.pop("capture_error", None)
    progress = st.progress(0.0, text=f"Reading {name}…")
    try:
        bundle = build_bundle(data, name, get_settings().max_packets,
                              progress=lambda fraction: progress.progress(fraction, text=f"Reading {name}…"))
        st.session_state["bundle"], st.session_state["bundle_key"] = bundle, key
    except CaptureError as error:
        st.session_state["bundle"], st.session_state["bundle_key"] = None, key
        st.session_state["capture_error"] = f"{name}: {error}"
    except Exception as error:      # last line of defence: never show a stack trace for a bad file
        st.session_state["bundle"], st.session_state["bundle_key"] = None, key
        st.session_state["capture_error"] = (f"{name}: the file could not be analysed "
                                             f"({type(error).__name__}: {error}).")
    finally:
        progress.empty()


def sidebar() -> None:
    with st.sidebar:
        st.markdown('<div class="nta-brand"><div class="nta-brand-mark">PS</div><div>'
                    '<div class="nta-brand-name">PacketScope</div>'
                    '<div class="nta-brand-sub">Network Traffic Analyzer</div></div></div>', unsafe_allow_html=True)
        theme.section("Capture file")
        uploaded = st.file_uploader("Upload a PCAP or PCAPNG file", type=["pcap", "pcapng", "cap"], key="uploader",
                                    help="The file is analysed on this computer only.")
        if uploaded is not None:
            st.session_state["use_sample"] = False
            load_capture(uploaded.getvalue(), uploaded.name, f"upload:{uploaded.file_id}")
        elif st.session_state.get("use_sample") and SAMPLE_PATH.exists():
            load_capture(SAMPLE_PATH.read_bytes(), SAMPLE_PATH.name, "sample")
        else:
            st.session_state["bundle"], st.session_state["bundle_key"] = None, None
            st.session_state.pop("capture_error", None)

        if uploaded is None and SAMPLE_PATH.exists():
            if st.session_state.get("use_sample"):
                if st.button("Close sample capture", icon=":material/close:", width="stretch"):
                    st.session_state["use_sample"] = False
                    st.rerun()
            elif st.button("Load synthetic sample capture", icon=":material/science:", width="stretch",
                           help="A generated demo capture (samples/sample_http.pcap), analysed by the same engine."):
                st.session_state["use_sample"] = True
                st.rerun()

        bundle = current_bundle()
        if bundle is not None:
            summary = bundle.summary
            theme.section("Loaded capture")
            if st.session_state.get("bundle_key") == "sample":
                st.markdown(theme.badge("Synthetic sample data", "warning"), unsafe_allow_html=True)
            theme.key_values([("File", summary["file_name"]), ("Packets", f"{summary['packet_count']:,}"),
                              ("Duration", theme.format_duration(summary["duration"])),
                              ("HTTP", f"{summary['http_transactions']:,} transactions")])
        settings = get_settings()
        theme.section("AI service")
        if settings.ai_ready:
            st.markdown(theme.badge(f"Gemini · {settings.gemini_model}", "good"), unsafe_allow_html=True)
        elif not settings.ai_enabled:
            st.markdown(theme.badge("AI disabled", "neutral"), unsafe_allow_html=True)
        else:
            st.markdown(theme.badge("No API key · local answers only", "warning"), unsafe_allow_html=True)


def landing() -> None:
    error = st.session_state.get("capture_error")
    if error:
        st.error(error, icon=":material/error:")
    st.markdown(
        '<div class="nta-hero"><h1>Understand a packet capture in seconds</h1>'
        '<p>Upload a <b>.pcap</b> or <b>.pcapng</b> file in the sidebar. PacketScope decodes every frame, rebuilds '
        'the TCP streams, pairs each HTTP request with its response and measures the response time — with the '
        'frame numbers you need to verify everything in Wireshark.</p></div>', unsafe_allow_html=True)
    features = [
        ("Overview", "Packets, duration, protocols, traffic over time and the busiest endpoints."),
        ("Packet Explorer", "Search and filter every frame; open any frame layer by layer."),
        ("HTTP Transactions", "Requests matched to responses with frames, status codes and response times."),
        ("AI Analyst", "Ask questions in English or Hebrew; every answer cites verified frames."),
        ("Insights", "Slow requests, errors, missing responses and incomplete TCP streams."),
    ]
    blocks = "".join(f'<div class="nta-card"><div class="nta-card-title">{theme.esc(title)}</div>'
                     f'<div class="nta-card-body">{theme.esc(text)}</div></div>' for title, text in features)
    st.markdown(f'<div class="nta-feature-grid">{blocks}</div>', unsafe_allow_html=True)
    st.caption("No capture at hand? Use “Load synthetic sample capture” in the sidebar.")


def page(render):
    """Wrap a page so that it shows the landing screen until a capture is loaded."""
    def run() -> None:
        bundle = current_bundle()
        if bundle is None:
            landing()
        else:
            render(bundle)
    run.__name__ = render.__module__.rsplit(".", 1)[-1]
    return run


pages = {
    "overview": st.Page(page(page_overview.render), title="Overview", icon=":material/dashboard:", url_path="overview", default=True),
    "packets": st.Page(page(page_packets.render), title="Packet Explorer", icon=":material/table_rows:", url_path="packets"),
    "http": st.Page(page(page_http.render), title="HTTP Transactions", icon=":material/swap_horiz:", url_path="http"),
    "ai": st.Page(page(page_ai.render), title="AI Analyst", icon=":material/network_intelligence:", url_path="ai"),
    "insights": st.Page(page(page_insights.render), title="Insights", icon=":material/insights:", url_path="insights"),
}
st.session_state["pages"] = pages
navigation = st.navigation(list(pages.values()))
sidebar()
navigation.run()
