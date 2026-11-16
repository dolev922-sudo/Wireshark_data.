"""Network Traffic Analyzer - analysis engine.

``analyze_capture`` is the single entry point used by the dashboard and tests:
bytes of a PCAP/PCAPNG file in, a fully populated ``CaptureAnalysis`` out.
"""

from __future__ import annotations

from typing import Callable, Optional

from .http_analyzer import analyze_http
from .models import CaptureAnalysis
from .parser import CaptureError, read_capture
from .tcp_reassembly import reassemble_tcp_streams

__all__ = ["analyze_capture", "CaptureAnalysis", "CaptureError"]


def analyze_capture(
    data: bytes,
    file_name: str = "capture",
    max_packets: int = 500_000,
    progress: Optional[Callable[[float], None]] = None,
) -> CaptureAnalysis:
    """Run the whole pipeline: read frames -> rebuild TCP streams -> HTTP/TLS."""
    analysis = read_capture(data, file_name=file_name, max_packets=max_packets, progress=progress)
    reassemble_tcp_streams(analysis)
    analyze_http(analysis)
    return analysis
