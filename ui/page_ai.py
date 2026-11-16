"""AI Analyst page: natural-language questions answered from locally verified data."""

from __future__ import annotations


import pandas as pd
import streamlit as st

from analyzer.ai_assistant import (SUGGESTED_QUESTIONS, AIAnswer, AIError, GeminiAssistant, build_context,
                                   local_answer)

from . import theme
from .state import Bundle, get_settings, slow_threshold_seconds

GEMINI, LOCAL = "Gemini", "Local engine (offline)"


def _evidence_table(answer: AIAnswer) -> pd.DataFrame:
    return pd.DataFrame([{
        "Reference": item.transaction_id if item.kind == "transaction" else f"Frame {item.frame}",
        "Extracted data (from the capture)": item.summary,
        "Time (s)": item.relative_time,
        "Timestamp (UTC)": theme.format_timestamp(item.timestamp),
        "Why it is cited": item.note,
    } for item in answer.evidence])


def render_answer(entry: dict) -> None:
    answer: AIAnswer = entry["answer"]
    if entry.get("notice"):
        st.warning(entry["notice"], icon=":material/cloud_off:")
    source = (theme.badge(f"Gemini · {answer.model}", "info") if answer.source == "gemini"
              else theme.badge("Local engine · no AI", "neutral"))
    if not answer.data_available:
        source += " " + theme.badge("Data not available in this capture", "warning")
    st.markdown(source, unsafe_allow_html=True)
    st.markdown(answer.text)          # Markdown only: raw HTML in an answer is not rendered
    for warning in answer.warnings:
        st.caption(f":material/info: {warning}")
    if answer.rejected_references:
        st.error("**Unverified references removed.** The following could not be confirmed against the capture and "
                 "must not be trusted:\n" + "\n".join(f"- {text}" for text in answer.rejected_references),
                 icon=":material/gpp_bad:")
    if answer.evidence:
        with st.expander(f"Verified evidence ({len(answer.evidence)})", expanded=True):
            st.caption("Each reference was checked against the uploaded capture. The values shown are read from the "
                       "local analysis, not from the AI model.")
            st.dataframe(_evidence_table(answer), hide_index=True, column_config={
                "Reference": st.column_config.TextColumn(width="small"),
                "Time (s)": st.column_config.NumberColumn(format="%.6f", width="small"),
                "Extracted data (from the capture)": st.column_config.TextColumn(width="large")})


def _chat_log_markdown(bundle: Bundle, chat: list[dict]) -> str:
    lines = [f"# AI Analyst log — {bundle.summary['file_name']}", "",
             f"Capture SHA-256: `{bundle.summary['sha256']}`", ""]
    for number, entry in enumerate(chat, start=1):
        answer: AIAnswer = entry["answer"]
        lines += [f"## Question {number}", "", entry["question"], "",
                  f"**Answered by:** {'Gemini ' + answer.model if answer.source == 'gemini' else 'local engine (no AI)'}", "",
                  answer.text, ""]
        if answer.evidence:
            lines.append("**Verified evidence:**")
            lines += [f"- {item.transaction_id or 'frame ' + str(item.frame)} — {item.summary}" for item in answer.evidence]
            lines.append("")
        if answer.rejected_references:
            lines.append("**Rejected references:**")
            lines += [f"- {text}" for text in answer.rejected_references]
            lines.append("")
    return "\n".join(lines)


def render(bundle: Bundle) -> None:
    settings = get_settings()
    analysis = bundle.analysis
    assistant = GeminiAssistant(settings)
    problem = assistant.availability()
    theme.page_header("AI Analyst", "Ask about this capture in English or Hebrew. Numbers come from the local engine; "
                                    "the AI only explains them.")
    if analysis.packet_count == 0:
        st.info("This capture contains no packets.", icon=":material/info:")
        return

    left, right = st.columns([3, 2], gap="large")
    with right:
        theme.section("AI service")
        if problem is None:
            st.markdown(theme.badge(f"Gemini ready · {settings.gemini_model}", "good"), unsafe_allow_html=True)
        else:
            st.markdown(theme.badge("Gemini not available", "warning"), unsafe_allow_html=True)
            st.caption(problem.user_message + " The local engine below still answers common questions.")
        consent = st.checkbox("Allow sending a sanitised summary to Gemini", key="ai_consent",
                              disabled=problem is not None)
        st.caption("Required before any capture-derived data leaves this computer.")
        options = [GEMINI, LOCAL] if (problem is None and consent) else [LOCAL]
        mode = st.radio("Answer with", options, key=f"ai_mode_{len(options)}", horizontal=True)
        with st.expander("What is sent to Gemini?"):
            st.markdown(
                "**Sent:** capture totals, protocol counts, busiest IP addresses, and for each HTTP transaction its "
                "method, host, URI path, status, frame numbers and timings; TLS server names; the findings list.\n\n"
                "**Never sent:** the capture file, packet payloads, HTTP bodies, cookies, Authorization headers, or "
                "the values of URL query parameters.")
            if st.toggle("Preview the exact data", key="ai_preview"):
                st.json(build_context(analysis, "", settings.ai_max_transactions, slow_threshold_seconds()), expanded=1)

    chat: list[dict] = st.session_state.setdefault("ai_chat", {}).setdefault(analysis.sha256, [])
    cache: dict = st.session_state.setdefault("ai_cache", {})
    with left:
        theme.section("Suggested questions")
        picked = None
        columns = st.columns(2)
        for index, suggestion in enumerate(SUGGESTED_QUESTIONS):
            if columns[index % 2].button(suggestion, key=f"ai_suggest_{index}", width="stretch"):
                picked = suggestion
    typed = st.chat_input("Ask a question about this capture…  /  שאלו שאלה על ההקלטה", max_chars=1000)
    question = (typed or picked or "").strip()

    with left:
        theme.section("Conversation")
        if not chat and not question:
            st.caption("No questions yet. Pick a suggestion above or type your own below.")
        for entry in chat:
            with st.chat_message("user"):
                st.markdown(entry["question"])
            with st.chat_message("assistant", avatar=":material/network_intelligence:"):
                render_answer(entry)

        if question:
            with st.chat_message("user"):
                st.markdown(question)
            with st.chat_message("assistant", avatar=":material/network_intelligence:"):
                entry = _answer(bundle, assistant, question, mode, chat, cache)
                render_answer(entry)
            chat.append(entry)
            st.rerun()      # clears the suggestion picker and stores the turn

        if chat:
            columns = st.columns([2.2, 1.6, 2])
            columns[0].download_button("Download Q&A log (Markdown)", _chat_log_markdown(bundle, chat),
                                       file_name="ai_analyst_log.md", mime="text/markdown", icon=":material/download:")
            if columns[1].button("Clear conversation", icon=":material/delete:"):
                chat.clear()
                st.rerun()


def _answer(bundle: Bundle, assistant: GeminiAssistant, question: str, mode: str, chat: list[dict], cache: dict) -> dict:
    """Produce one chat entry. Falls back to the local engine if Gemini fails."""
    analysis = bundle.analysis
    threshold = slow_threshold_seconds()
    if mode != GEMINI:
        return {"question": question, "answer": local_answer(analysis, question, threshold)}

    cache_key = (analysis.sha256, assistant.settings.gemini_model, question)
    if cache_key in cache:                     # identical question: reuse, no new API call
        return {"question": question, "answer": cache[cache_key]}
    history = [(entry["question"], entry["answer"].text) for entry in chat if entry["answer"].source == "gemini"]
    try:
        with st.spinner("Asking Gemini…"):
            answer = assistant.ask(analysis, question, history=history)
        cache[cache_key] = answer
        return {"question": question, "answer": answer}
    except AIError as error:
        return {"question": question, "answer": local_answer(analysis, question, threshold),
                "notice": f"{error.user_message} Showing the local engine’s answer instead."}



