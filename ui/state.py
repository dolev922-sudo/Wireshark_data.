"""Session state: the analysed capture and everything derived from it."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Optional

import pandas as pd
import streamlit as st

from analyzer import CaptureAnalysis, analytics, analyze_capture
from analyzer.config import Settings, load_settings


@dataclass
class Bundle:
    """One analysed capture plus the tables every page needs."""

    analysis: CaptureAnalysis
    packets: pd.DataFrame
    transactions: pd.DataFrame
    streams: pd.DataFrame
    tls: pd.DataFrame
    endpoints: pd.DataFrame
    summary: dict


@st.cache_resource
def get_settings() -> Settings:
    return load_settings()


def build_bundle(data: bytes, file_name: str, max_packets: int, progress=None) -> Bundle:
    analysis = analyze_capture(data, file_name=file_name, max_packets=max_packets, progress=progress)
    packets = analytics.packets_dataframe(analysis)
    return Bundle(
        analysis=analysis, packets=packets,
        transactions=analytics.transactions_dataframe(analysis),
        streams=analytics.streams_dataframe(analysis),
        tls=analytics.tls_dataframe(analysis),
        endpoints=analytics.endpoint_statistics(packets),
        summary=analytics.capture_summary(analysis, packets),
    )


def current_bundle() -> Optional[Bundle]:
    return st.session_state.get("bundle")


def slow_threshold_seconds() -> float:
    return st.session_state.get("slow_threshold_ms", get_settings().slow_threshold_seconds * 1000) / 1000.0


def go_to(page_key: str, **preset) -> None:
    """Jump to another page, pre-filling some of its filter widgets."""
    for key, value in preset.items():
        st.session_state[key] = value
    st.switch_page(st.session_state["pages"][page_key])


def parse_port(text: str) -> tuple[Optional[int], str]:
    """Parse a port typed by the user. Returns (port or None, error message)."""
    text = (text or "").strip()
    if not text:
        return None, ""
    if text.isdigit() and 0 <= int(text) <= 65535:
        return int(text), ""
    return None, "Port must be a number between 0 and 65535."


def parse_integer(text: str, label: str) -> tuple[Optional[int], str]:
    text = (text or "").strip()
    if not text:
        return None, ""
    if text.isdigit():
        return int(text), ""
    return None, f"{label} must be a whole number."
