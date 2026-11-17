# Assignment compliance checklist — Part C (Dashboard V1)

> **Important.** The assignment PDF (`מטלה 1 - 2026-2027.pdf`) was **not available** when this checklist was
> written, so the rows below follow the written project brief, not the PDF's own numbering.
> **Before submitting:** open the PDF, write the matching requirement number (23–34) in the first column, and
> add a row for anything the PDF asks that is not listed here. If the PDF and this project disagree, the PDF wins.

Status legend: ✅ implemented and covered by an automated test · ☑️ implemented, checked manually in the browser ·
⚠️ implemented but not fully verifiable here.

| PDF req. # | Requirement (from the brief) | Where implemented | How it was verified | Status |
|---|---|---|---|---|
| ___ | Upload PCAP and PCAPNG files | `app.py` (sidebar uploader), `analyzer/parser.py` | `test_pcap_is_parsed`, `test_pcapng_gives_identical_results`; real upload of a `.pcapng` in a browser | ✅ |
| ___ | Packet count | `CaptureAnalysis.packet_count`, Overview KPI | `test_capture_summary`, `test_full_app_with_sample_capture` | ✅ |
| ___ | Capture start / end time and duration | `analytics.capture_summary`, Overview | `test_timestamps_and_duration` | ✅ |
| ___ | Source and destination IP addresses | `parser.decode_frame`, Packet Explorer, Overview endpoints | `test_addresses_ports_and_lengths`, `test_endpoint_statistics`, Scapy cross-check test | ✅ |
| ___ | Main protocols and traffic volume | `analytics.protocol_distribution`, Overview chart + table | `test_protocol_distribution_sums_to_packet_count` | ✅ |
| ___ | Interactive charts | `ui/charts.py` (traffic over time, protocols, endpoints, response times, status codes) | Rendered in a browser; hover tooltips and Packets/Bytes switches used | ☑️ |
| ___ | Identify HTTP requests and responses | `analyzer/http_analyzer.py` | `test_http_get_fields`, `test_http_post_fields` | ✅ |
| ___ | Match each request with its response | `http_analyzer._match_stream` (per stream, by order) | `test_interleaved_connections_are_matched_per_stream`, `test_two_messages_in_one_segment_and_keep_alive_order`, gap / orphan tests | ✅ |
| ___ | Method, host, URI, IPs, ports, status code | `HttpTransaction`, HTTP Transactions table | `test_http_get_fields`, `test_transactions_table` | ✅ |
| ___ | Request frame and response frame numbers | `HttpTransaction.request_frame` / `response_frame` | `test_frame_numbers_follow_file_order`, `test_response_split_across_segments` | ✅ |
| ___ | Request / response timestamps and response time | `HttpTransaction.response_time`, `time_to_first_byte` | `test_response_time_is_frame_timestamp_difference` | ✅ |
| ___ | Reproduce the manual HTTP analysis (Parts A/B) automatically | HTTP Transactions page + README §4 (Wireshark comparison steps) | Must be compared with **your own** Part A/B results on your capture | ⚠️ |
| ___ | AI-assisted questions about the capture | `analyzer/ai_assistant.py`, AI Analyst page (Gemini via `google-genai`) | Fake-client tests; real SDK call reached Google with an invalid key. **A real answer needs your API key.** | ⚠️ |
| ___ | AI answers backed by evidence (frames, IDs, timestamps) | `validate_evidence`, evidence table in the chat | `test_fabricated_evidence_is_rejected`, `test_ai_page_requires_consent_before_calling_gemini` | ✅ |
| ___ | Handling of missing data / uncertainty | Warnings on transactions, `data_available` flag, HTTPS metadata only | `test_request_without_response`, `test_https_never_produces_http_transactions`, `test_data_not_available_answer` | ✅ |
| ___ | Creativity: extra features | **Investigation filters** (Insights → Investigation filters) and **HTTP performance insights** (slow / errors / incomplete) | `test_transaction_filters`, `test_insights_report_slow_errors_and_missing_with_evidence`, `test_insights_threshold_slider_changes_results` | ✅ |
| ___ | Readable code, meaningful names, comments | Module docstrings explain each algorithm; small named functions | Code review | ☑️ |
| ___ | Clear run instructions / reproducibility | `README.md`, `requirements.txt`, `.env.example`, `run.bat` | Fresh `pip install` + `streamlit run app.py` + `pytest` executed (Linux, Python 3.13). **Not run on Windows here.** | ⚠️ |
| ___ | AI usage documentation | `docs/AI_USAGE_AND_PROMPTS.md`, `docs/AI_VERIFICATION_5_QUESTIONS.md`, `docs/AI_MISTAKES_LOG.md` | Templates — you complete them with your own runs | ⚠️ |

## Things only you can complete

1. Compare the dashboard with your manual Wireshark results on **your** capture (README §4) and note any difference.
2. Add your Gemini API key, ask the five questions, and fill in `AI_VERIFICATION_5_QUESTIONS.md`.
3. Record at least one AI mistake and its correction in `AI_MISTAKES_LOG.md`.
4. Run the app once on your Windows computer and add screenshots to your report.
5. Fill in the PDF requirement numbers above.
