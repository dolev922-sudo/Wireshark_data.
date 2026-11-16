"""AI Analyst: sanitised context, evidence validation, Gemini failures, missing credentials.

No test talks to the real Gemini service - a fake client is injected instead.
"""

import json
from types import SimpleNamespace

import pytest
from google.genai import errors

from analyzer import analyze_capture
from analyzer.ai_assistant import (AIError, GeminiAssistant, build_context, find_unverified_mentions, local_answer,
                                   normalize_transaction_id, sanitize_uri, validate_evidence)
from analyzer.config import Settings, load_settings
from tools.capture_builder import CaptureBuilder, TcpConversation, http_request, http_response

from .conftest import CLIENT, SERVER


def make_settings(**overrides):
    values = dict(gemini_api_key="test-key", gemini_model="gemini-2.5-flash", ai_enabled=True,
                  slow_threshold_seconds=0.5, max_packets=500_000, ai_max_transactions=150, ai_timeout_seconds=30.0)
    values.update(overrides)
    return Settings(**values)


class FakeClient:
    """Stands in for genai.Client: returns a canned reply or raises a canned error."""

    def __init__(self, reply=None, error=None):
        self.reply, self.error, self.calls = reply, error, []
        self.models = SimpleNamespace(generate_content=self._generate)

    def _generate(self, **kwargs):
        self.calls.append(kwargs)
        if self.error:
            raise self.error
        return SimpleNamespace(text=self.reply)


def reply(answer, evidence, data_available=True):
    return json.dumps({"answer": answer, "data_available": data_available, "evidence": evidence})


@pytest.fixture
def secret_capture():
    """A capture full of things that must never reach the AI service."""
    capture = CaptureBuilder()
    tcp = TcpConversation(capture, CLIENT, SERVER, 50000)
    tcp.handshake()
    tcp.client(http_request(
        "POST", "/login?user=alice&token=TOPSECRETTOKEN", "bank.example", body=b"password=HUNTER2PASSWORD",
        extra_headers="Authorization: Basic QUxJQ0U6U0VDUkVU\r\nCookie: sid=COOKIESECRET\r\n"))
    tcp.server(http_response(200, "OK", b"PRIVATE-ACCOUNT-BALANCE", extra_headers="Set-Cookie: sid=NEWCOOKIESECRET\r\n"),
               delay=0.05)
    return analyze_capture(capture.to_bytes())


# ---- sanitising ----------------------------------------------------------------
def test_context_excludes_secrets_and_payloads(secret_capture):
    context = build_context(secret_capture, "what happened in frame 4?")
    serialized = json.dumps(context)
    for secret in ("TOPSECRETTOKEN", "alice", "HUNTER2PASSWORD", "QUxJQ0U6U0VDUkVU", "COOKIESECRET",
                   "NEWCOOKIESECRET", "PRIVATE-ACCOUNT-BALANCE"):
        assert secret not in serialized
    transaction = context["http"]["transactions"][0]
    assert transaction["uri"] == "/login?user=<redacted>&token=<redacted>"
    assert transaction["sends_credentials_or_cookies"] is True
    assert transaction["host"] == "bank.example" and transaction["status"] == 200
    assert context["frames_mentioned_in_question"][0]["info"] == "POST /login?user=<redacted>&token=<redacted> HTTP/1.1"


def test_sanitize_uri():
    assert sanitize_uri("/a/b") == "/a/b"
    assert sanitize_uri("/s?q=cats&page=2") == "/s?q=<redacted>&page=<redacted>"
    assert sanitize_uri("http://user:pw@host.example/p?k=v") == "http://host.example/p?k=<redacted>"
    assert sanitize_uri("") == ""


def test_context_numbers_come_from_local_engine(basic):
    analysis, frames = basic
    context = build_context(analysis, f"tell me about {SERVER} and 203.0.113.9")
    assert context["capture"]["packet_count"] == 15
    assert context["http"]["total_transactions"] == 2
    assert context["http"]["transactions"][0]["request_frame"] == frames["get"]
    assert context["http"]["transactions"][0]["response_time_ms"] == pytest.approx(50.0, abs=0.01)
    mentioned = {item["ip"]: item for item in context["ip_addresses_mentioned_in_question"]}
    assert mentioned[SERVER]["present"] is True and mentioned["203.0.113.9"]["present"] is False


def test_large_captures_send_a_bounded_selection():
    capture = CaptureBuilder()
    tcp = TcpConversation(capture, CLIENT, SERVER, 50000)
    tcp.handshake()
    for number in range(30):
        tcp.client(http_request("GET", f"/item/{number}", "example.com"))
        tcp.server(http_response(500 if number == 27 else 200, "X", b"ok"))
    context = build_context(analyze_capture(capture.to_bytes()), max_transactions=10)
    assert context["http"]["total_transactions"] == 30
    assert len(context["http"]["transactions"]) == 10
    assert "Only part" in context["http"]["note"]
    assert any(t["status"] == 500 for t in context["http"]["transactions"])      # errors are kept first


# ---- evidence validation -------------------------------------------------------
def test_valid_evidence_is_rebuilt_from_local_data(basic):
    analysis, frames = basic
    verified, rejected = validate_evidence(analysis, [
        {"transaction_id": "T0001", "note": "the GET"},
        {"frame": frames["dns_query"], "note": "dns"},
        {"transaction_id": "t2", "frame": frames["post"], "note": "the POST"},
    ])
    assert rejected == []
    assert [item.transaction_id for item in verified] == ["T0001", "", "T0002"]
    assert "GET example.com/index.html" in verified[0].summary and "50.0 ms" in verified[0].summary
    assert verified[0].timestamp == analysis.packet(frames["get"]).timestamp
    assert verified[1].frame == frames["dns_query"] and verified[1].summary.startswith("DNS")


def test_fabricated_evidence_is_rejected(basic):
    analysis, frames = basic
    verified, rejected = validate_evidence(analysis, [
        {"frame": 9999, "note": "invented frame"},
        {"transaction_id": "T0099", "note": "invented transaction"},
        {"frame": frames["dns_query"], "transaction_id": "T0001", "note": "frame from another exchange"},
        {"frame": "abc", "note": "garbage"},
        {"note": "no reference at all"},
        "not even an object",
        {"frame": -3, "note": "negative"},
    ])
    assert verified == []
    assert len(rejected) == 7
    assert any("Frame 9999 does not exist" in text for text in rejected)
    assert any("T0099" in text for text in rejected)
    assert any("not part of transaction T0001" in text for text in rejected)


def test_unverified_mentions_in_answer_text(basic):
    analysis, _ = basic
    problems = find_unverified_mentions(analysis, "See frame 6 and frame 4242, also T0002 and T0500.")
    assert len(problems) == 2 and "4242" in problems[0] and "T0500" in problems[1]
    assert normalize_transaction_id("t7") == "T0007" and normalize_transaction_id("12") == "T0012"


def test_gemini_answer_with_mixed_evidence(basic):
    analysis, frames = basic
    client = FakeClient(reply("T0002 was slowest, see frame 7777.", [
        {"transaction_id": "T0002", "note": "120 ms"}, {"frame": 7777, "note": "made up"}]))
    answer = GeminiAssistant(make_settings(), client=client).ask(analysis, "Which request was slowest?")
    assert answer.source == "gemini" and answer.model == "gemini-2.5-flash"
    assert [item.transaction_id for item in answer.evidence] == ["T0002"]
    assert "120.0 ms" in answer.evidence[0].summary                 # shown value is the locally measured one
    assert len(answer.rejected_references) == 2                     # bad evidence entry + bad mention in the text
    call = client.calls[0]
    assert call["model"] == "gemini-2.5-flash"
    assert call["config"]["response_mime_type"] == "application/json"
    assert "QUESTION: Which request was slowest?" in call["contents"]


def test_raw_capture_bytes_are_never_sent(secret_capture):
    client = FakeClient(reply("ok", []))
    GeminiAssistant(make_settings(), client=client).ask(secret_capture, "summarise", history=[("q", "a")])
    sent = json.dumps(client.calls[0], default=str)
    assert "HUNTER2PASSWORD" not in sent and "COOKIESECRET" not in sent and "PRIVATE-ACCOUNT-BALANCE" not in sent
    assert isinstance(client.calls[0]["contents"], str)


def test_unstructured_reply_is_flagged_as_unverified(basic):
    analysis, _ = basic
    answer = GeminiAssistant(make_settings(), client=FakeClient("Just some prose about frame 99999.")).ask(analysis, "hi")
    assert answer.evidence == [] and answer.text.startswith("Just some prose")
    assert any("structured format" in warning for warning in answer.warnings)
    assert any("99999" in text for text in answer.rejected_references)


def test_code_fenced_json_is_accepted(basic):
    analysis, _ = basic
    fenced = "```json\n" + reply("fine", [{"transaction_id": "T0001", "note": "n"}]) + "\n```"
    answer = GeminiAssistant(make_settings(), client=FakeClient(fenced)).ask(analysis, "q")
    assert answer.text == "fine" and len(answer.evidence) == 1


def test_data_not_available_answer(basic):
    analysis, _ = basic
    client = FakeClient(reply("The capture has no HTTPS content.", [], data_available=False))
    answer = GeminiAssistant(make_settings(), client=client).ask(analysis, "What was the HTTPS page body?")
    assert answer.data_available is False and answer.evidence == [] and answer.warnings == []


# ---- failures ------------------------------------------------------------------
@pytest.mark.parametrize("error, kind", [
    (errors.ClientError(429, {"error": {"code": 429, "message": "Quota exceeded", "status": "RESOURCE_EXHAUSTED"}}), "quota"),
    (errors.ClientError(400, {"error": {"code": 400, "message": "API key not valid. Please pass a valid API key.",
                                        "status": "INVALID_ARGUMENT"}}), "invalid_key"),
    (errors.ClientError(403, {"error": {"code": 403, "message": "denied", "status": "PERMISSION_DENIED"}}), "invalid_key"),
    (errors.ClientError(404, {"error": {"code": 404, "message": "models/x is not found", "status": "NOT_FOUND"}}),
     "model_unavailable"),
    (errors.ServerError(503, {"error": {"code": 503, "message": "overloaded", "status": "UNAVAILABLE"}}), "server"),
    (TimeoutError("timed out"), "timeout"),
    (ConnectionError("no route to host"), "network"),
    (RuntimeError("something odd"), "unknown"),
])
def test_gemini_api_errors_become_clear_messages(basic, error, kind):
    analysis, _ = basic
    assistant = GeminiAssistant(make_settings(), client=FakeClient(error=error))
    with pytest.raises(AIError) as caught:
        assistant.ask(analysis, "anything")
    assert caught.value.kind == kind
    assert caught.value.user_message and "Traceback" not in caught.value.user_message


@pytest.mark.parametrize("text", ["", None, "   "])
def test_empty_gemini_response(basic, text):
    analysis, _ = basic
    with pytest.raises(AIError) as caught:
        GeminiAssistant(make_settings(), client=FakeClient(text)).ask(analysis, "q")
    assert caught.value.kind == "empty_response"


@pytest.mark.parametrize("key", ["", "your_api_key_here", "   "])
def test_missing_api_key(basic, key):
    analysis, _ = basic
    assistant = GeminiAssistant(make_settings(gemini_api_key=key))
    assert assistant.availability().kind == "missing_key"
    with pytest.raises(AIError) as caught:
        assistant.ask(analysis, "q")
    assert caught.value.kind == "missing_key" and "GEMINI_API_KEY" in caught.value.user_message


def test_ai_disabled(basic):
    analysis, _ = basic
    client = FakeClient(reply("x", []))
    with pytest.raises(AIError) as caught:
        GeminiAssistant(make_settings(ai_enabled=False), client=client).ask(analysis, "q")
    assert caught.value.kind == "disabled" and client.calls == []


def test_empty_question_makes_no_api_call(basic):
    analysis, _ = basic
    client = FakeClient(reply("x", []))
    with pytest.raises(AIError):
        GeminiAssistant(make_settings(), client=client).ask(analysis, "   ")
    assert client.calls == []


def test_settings_load_from_env_file(tmp_path):
    import os
    names = ("GEMINI_API_KEY", "GEMINI_MODEL", "AI_ENABLED", "SLOW_THRESHOLD_MS")
    saved = {name: os.environ.pop(name) for name in names if name in os.environ}
    try:
        env_file = tmp_path / ".env"
        env_file.write_text("GEMINI_API_KEY=abc123\nGEMINI_MODEL=gemini-2.5-flash-lite\nAI_ENABLED=false\nSLOW_THRESHOLD_MS=250\n")
        settings = load_settings(env_file)
        assert (settings.gemini_api_key, settings.gemini_model, settings.ai_enabled) == ("abc123", "gemini-2.5-flash-lite", False)
        assert settings.slow_threshold_seconds == 0.25 and settings.has_api_key and not settings.ai_ready
        for name in names:
            os.environ.pop(name, None)
        defaults = load_settings(tmp_path / "missing.env")
        assert defaults.gemini_model == "gemini-2.5-flash" and defaults.ai_enabled and not defaults.has_api_key
    finally:                       # load_dotenv writes into os.environ: leave no trace for other tests
        for name in names:
            os.environ.pop(name, None)
        os.environ.update(saved)


# ---- local fallback ------------------------------------------------------------
def test_local_answers_are_evidence_backed(basic):
    analysis, frames = basic
    slowest = local_answer(analysis, "Which HTTP request had the longest response time?")
    assert slowest.source == "local" and "T0002" in slowest.text and "120.0 ms" in slowest.text
    assert slowest.evidence[0].transaction_id == "T0002"
    assert "No HTTP error" in local_answer(analysis, "Were there any HTTP errors?").text
    assert "Every captured HTTP request" in local_answer(analysis, "Which requests did not receive a response?").text
    frame_answer = local_answer(analysis, f"What is frame {frames['get']}?")
    assert "GET /index.html" in frame_answer.text and frame_answer.evidence[0].frame == frames["get"]
    assert local_answer(analysis, "what is frame 500?").data_available is False
    assert find_unverified_mentions(analysis, slowest.text) == []


def test_local_answers_in_hebrew(basic):
    analysis, _ = basic
    summary = local_answer(analysis, "כמה חבילות יש בהקלטה?")
    assert "15" in summary.text and "חבילות" in summary.text and summary.warnings == []
    protocols = local_answer(analysis, "אילו פרוטוקולים מופיעים?")
    assert "HTTP: 4" in protocols.text and "DNS: 2" in protocols.text and protocols.evidence
