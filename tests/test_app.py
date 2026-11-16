"""Dashboard tests with Streamlit's AppTest: pages render and controls change the results.

These run the real page code against the bundled synthetic sample capture.
"""

from pathlib import Path

import pytest
from streamlit.testing.v1 import AppTest

ROOT = Path(__file__).resolve().parent.parent
PAGES = ["page_overview", "page_packets", "page_http", "page_ai", "page_insights"]


def _page_script(page_name: str, capture: str = "sample_http.pcap"):
    """Runs inside AppTest: load the sample and render one page."""
    import importlib
    from pathlib import Path

    import streamlit as st

    from ui import theme
    from ui.state import build_bundle

    root = Path.cwd()
    if "bundle" not in st.session_state:
        data = (root / "samples" / capture).read_bytes()
        st.session_state["bundle"] = build_bundle(data, capture, 500_000)
    st.session_state.setdefault("pages", {})
    theme.apply_theme()
    importlib.import_module(f"ui.{page_name}").render(st.session_state["bundle"])


def run_page(page_name: str, **kwargs) -> AppTest:
    return AppTest.from_function(_page_script, args=(page_name,), kwargs=kwargs, default_timeout=60).run()


def markdown_text(app: AppTest) -> str:
    return "\n".join(block.value for block in app.markdown)


def test_landing_page_without_capture(monkeypatch):
    monkeypatch.chdir(ROOT)
    app = AppTest.from_file(str(ROOT / "app.py"), default_timeout=60).run()
    assert not app.exception
    assert "Understand a packet capture" in markdown_text(app)


def test_full_app_with_sample_capture(monkeypatch):
    monkeypatch.chdir(ROOT)
    app = AppTest.from_file(str(ROOT / "app.py"), default_timeout=60)
    app.session_state["use_sample"] = True
    app.run()
    assert not app.exception
    text = markdown_text(app)
    assert "Total packets" in text and ">123<" in text          # real packet count of the sample
    assert "Synthetic sample data" in text


@pytest.mark.parametrize("page_name", PAGES)
@pytest.mark.parametrize("capture", ["sample_http.pcap", "sample_http.pcapng"])
def test_every_page_renders(monkeypatch, page_name, capture):
    monkeypatch.chdir(ROOT)
    app = run_page(page_name, capture=capture)
    assert not app.exception, app.exception


def test_packet_explorer_filters_change_the_table(monkeypatch):
    monkeypatch.chdir(ROOT)
    app = run_page("page_packets")
    assert "Showing **123** of 123 packets" in markdown_text(app)
    app.multiselect(key="px_protocols").set_value(["DNS"]).run()
    assert "Showing **12** of 123 packets" in markdown_text(app)
    assert set(app.dataframe[0].value["protocol"]) == {"DNS"}
    app.multiselect(key="px_protocols").set_value([])
    app.text_input(key="px_port").set_value("8080").run()
    assert set(app.dataframe[0].value["dst_port"]) | set(app.dataframe[0].value["src_port"]) >= {8080}
    app.text_input(key="px_port").set_value("99999").run()
    assert any("Port must be a number" in error.value for error in app.error)


def test_http_filters_change_the_table(monkeypatch):
    monkeypatch.chdir(ROOT)
    app = run_page("page_http")
    assert "Showing **13** of 13 transactions" in markdown_text(app)
    app.multiselect(key="http_methods").set_value(["PUT"]).run()
    assert "Showing **1** of 13 transactions" in markdown_text(app)
    table = app.dataframe[0].value
    assert list(table["status"]) == [500] and list(table["id"]) == ["T0008"]
    app.multiselect(key="http_methods").set_value([])
    app.slider(key="http_rt").set_value((500.0, 1000.0)).run()
    assert list(app.dataframe[0].value["id"]) == ["T0013"]


def test_ai_page_answers_locally_without_api_key(monkeypatch):
    monkeypatch.chdir(ROOT)
    monkeypatch.setenv("GEMINI_API_KEY", "")
    app = run_page("page_ai")
    assert "Gemini not available" in markdown_text(app)
    assert app.checkbox(key="ai_consent").disabled
    app.chat_input[0].set_value("Which HTTP request had the longest response time?").run()
    assert not app.exception
    text = markdown_text(app)
    assert "T0007" in text and "1840.5 ms" in text and "Local engine" in text


def test_insights_threshold_slider_changes_results(monkeypatch):
    monkeypatch.chdir(ROOT)
    app = run_page("page_insights")
    assert "2 slow HTTP transaction(s)" in markdown_text(app)
    app.slider(key="slow_threshold_ms").set_value(100).run()
    assert "4 slow HTTP transaction(s)" in markdown_text(app)
    app.multiselect(key="inv_classes").set_value(["5xx"]).run()
    assert "Matching HTTP transactions" in markdown_text(app)


def test_frame_dissection_shows_real_layers(monkeypatch):
    monkeypatch.chdir(ROOT)
    from analyzer import analyze_capture
    from ui.page_packets import dissect, hex_dump
    analysis = analyze_capture((ROOT / "samples" / "sample_http.pcap").read_bytes())
    text = dissect(analysis, 7)
    assert "###[ Ethernet ]###" in text and "###[ TCP ]###" in text and "GET / HTTP/1.1" in text
    assert hex_dump(analysis.raw_frames[6]).startswith("0000  02 00 00 00 00 02")
