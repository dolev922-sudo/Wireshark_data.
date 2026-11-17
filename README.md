# PacketScope — Network Traffic Analyzer Dashboard (V1)

An educational dashboard that reads a **PCAP / PCAPNG** capture, rebuilds the TCP streams, pairs every
**HTTP request with its response**, measures response times and lets you ask questions about the capture in
**English or Hebrew**. Every number is computed locally from the packets; the AI only explains verified results.

Built for the Computer Networks course assignment (Part C — Dashboard V1).

> **Status of the assignment mapping:** the assignment PDF was not available when this project was generated,
> so [`docs/ASSIGNMENT_CHECKLIST.md`](docs/ASSIGNMENT_CHECKLIST.md) maps the implementation to the written
> project brief. Fill in the requirement numbers 23–34 from the PDF before submitting.

---

## 1. Quick start (Windows)

Requires **Python 3.11 or newer** (developed and tested on Python 3.13).

```bat
git clone <your repository URL>
cd Wireshark_data.

py -3 -m venv .venv
.venv\Scripts\activate
pip install -r requirements.txt

copy .env.example .env
streamlit run app.py
```

The dashboard opens at <http://localhost:8501>. You can also double-click `run.bat`.
On macOS / Linux use `python3 -m venv .venv && source .venv/bin/activate` and `cp .env.example .env`.

No Npcap/WinPcap is needed: the app only *reads* capture files, it never sniffs the network.

### Configure Gemini (optional)

1. Create a free API key at <https://aistudio.google.com/app/apikey>.
2. Edit `.env`:

   ```ini
   GEMINI_API_KEY=your_api_key_here
   GEMINI_MODEL=gemini-2.5-flash
   AI_ENABLED=true
   ```
3. Restart the app. The sidebar shows `Gemini · gemini-2.5-flash` when the key is loaded.

`.env` is listed in `.gitignore` and must never be committed. Without a key the whole dashboard still works,
and the AI Analyst page answers common questions with a built-in local (non-AI) engine.

Optional settings: `SLOW_THRESHOLD_MS` (default 500), `MAX_PACKETS` (500000), `AI_MAX_TRANSACTIONS` (150),
`AI_TIMEOUT_SECONDS` (45). Upload size limit: `.streamlit/config.toml` → `maxUploadSize` (300 MB).

### Run the tests

```bat
python -m pytest
```

108 automated tests; none of them needs a network connection or an API key.

---

## 2. Using the dashboard

Upload a `.pcap` / `.pcapng` file in the sidebar (or press **Load synthetic sample capture** to try the app with
the generated demo file in `samples/`; it is clearly labelled as synthetic).

| Page | What you get |
|---|---|
| **Overview** | KPI cards (packets, duration, HTTP transactions, unique IPs, TLS sessions), traffic over time, protocol distribution, busiest endpoints, capture timestamps. |
| **Packet Explorer** | Every frame in file order. Filter by text, protocol, IP, port, TCP stream, frame range, time range, TCP issues. Select a row for decoded fields, a full Scapy layer dissection and a hex dump. CSV export. |
| **HTTP Transactions** | One row per request/response pair: method, host, URI, status, request/response frame, timestamps, response time. Filter and sort; select a row for headers, a timing bar and a step-by-step explanation of how the pair was reconstructed. HTTPS sessions are listed separately with metadata only. |
| **AI Analyst** | Chat in English or Hebrew. Answers list **verified evidence** (frame numbers, transaction IDs, timestamps, extracted data). Download the Q&A log as Markdown for your report. |
| **Insights** | Findings with evidence (slow requests, 4xx/5xx, missing responses, incomplete TCP streams, resets, retransmissions, cleartext credentials, failed DNS), HTTP performance charts with an adjustable slow threshold, TCP stream health, and combined **investigation filters**. |

All times in tables are **seconds since the first packet**; absolute timestamps are shown in **UTC**.

---

## 3. How it works

```
bytes of the file
   │  analyzer/parser.py          read frames, decode Ethernet/IP/TCP/UDP/…   → PacketRecord per frame
   │  analyzer/tcp_reassembly.py  group into connections, order bytes by seq  → TcpStream (two directions)
   │  analyzer/http_analyzer.py   parse HTTP messages, match pairs, TLS info  → HttpTransaction / TlsSession
   │  analyzer/analytics.py       tables, statistics, filters, insights       → pandas DataFrames
   ▼
ui/*.py (Streamlit pages)      analyzer/ai_assistant.py (Gemini + evidence validation)
```

### 3.1 Packet parser (`analyzer/parser.py`)

1. **Format check.** The first 4 bytes (magic number) identify PCAP or PCAPNG. Anything else is rejected with a
   clear message — the app never guesses.
2. **Reading.** Scapy's `RawPcapReader` / `RawPcapNgReader` returns the raw bytes and timestamp of each frame in
   file order. The position in the file is the **frame number** (1-based, identical to Wireshark's `frame.number`).
3. **Decoding.** Small explicit functions decode link layer (Ethernet, VLAN, Linux cooked, loopback, raw IP) →
   IPv4 / IPv6 / ARP → TCP / UDP / ICMP. Every length is checked first, so a truncated frame gets a
   `decode_error` note instead of a crash or an invented value. Ethernet padding is not counted as payload.
4. **Protocol label + how it was identified.** Each packet carries one of: *verified from payload* (HTTP, TLS,
   DNS, DHCP, SSDP), *identified from header* (ARP, ICMP), *guessed from port* (e.g. NTP, QUIC), *transport only*
   (plain TCP/UDP such as bare ACKs), or *unknown/unsupported*. Unknown traffic is counted but never relabelled.
5. Raw bytes are kept so any single frame can be fully dissected by Scapy on demand in the Packet Explorer.

Damaged input is handled without failing: an empty or non-capture file is rejected; a capture cut off
mid-frame keeps all earlier frames and shows a warning; unsupported link types are reported.

### 3.2 TCP stream reconstruction (`analyzer/tcp_reassembly.py`)

HTTP rides on TCP, which is a *byte stream*: a message can be split over many packets, repeated, reordered, or
partly missing. So before parsing HTTP:

1. **Connections.** Packets with the same two `(IP, port)` endpoints form a connection. A new SYN with a different
   initial sequence number starts a new connection on reused ports. Connections are numbered in order of
   appearance (the same idea as Wireshark's `tcp.stream`).
2. **Sequence numbers → offsets.** SYN sequence number + 1 is byte 0 of that direction (32-bit wrap-around is
   handled). Without a SYN, the lowest sequence number seen is byte 0 and the stream is flagged *starts mid-stream*.
3. **Placement by sequence number, not arrival order.** For every segment we check which bytes are already known:
   all known → **retransmission** (ignored; the first copy wins); fills a hole → **out-of-order** (accepted in the
   right place); otherwise new data.
4. **Gaps.** Bytes that never appear leave a hole. The direction is split into contiguous chunks and the number
   of missing bytes is recorded — data around a hole is never glued together.
5. **Byte → frame map.** Each chunk remembers which frame supplied which bytes, so the HTTP parser can say exactly
   which frame holds the first and the last byte of a message.

### 3.3 Matching requests to responses (`analyzer/http_analyzer.py`)

Matching is **per TCP connection, by position in the byte stream — never by closeness in time.**
HTTP/1.1 requires a server to answer the requests of one connection in the order they were sent, therefore:

> response number *k* on a connection answers request number *k* on that connection.

Safeguards:

- `1xx` responses (e.g. `100 Continue`) are attached to the pending request and do not consume it.
- A response that starts before the next pending request was sent cannot be its answer → **orphan response**
  (typical when the capture began mid-connection). No response time is reported for it.
- If the stream has **missing bytes**, a message may have been lost, so pairs found after the gap are shown as
  **uncertain** with a warning; a request whose successor was already sent before the next response is reported
  as *unanswered* rather than shifting every later pair.
- Requests still waiting at the end are reported as **no response captured** (with the likely reason: reset,
  missing bytes, or capture ended).
- Message boundaries follow the HTTP rules: `Transfer-Encoding: chunked`, then `Content-Length`, else no body for
  requests / read-until-close for responses; `HEAD`, `1xx`, `204`, `304` have no body.
- Client and server roles come from the content (who sends requests), not from who sent the first packet.
- HTTP is detected by content, so it is found on any port.

### 3.4 Response time

```
response time = timestamp(frame that completes the response) − timestamp(frame that completes the request)
```

This follows Wireshark's default behaviour, where a reassembled HTTP message is shown on its **last** TCP segment
and `http.time` is measured to that frame. The dashboard also shows **time to first byte** (request frame → first
frame of the response). For single-segment messages both values are equal.

### 3.5 HTTPS

Encrypted traffic is never guessed. For TLS connections the app reports only what is visible: server name (SNI),
offered ALPN, negotiated TLS version, Client/Server Hello frames and byte counts. No HTTP transaction is created.

### 3.6 AI answers and evidence validation (`analyzer/ai_assistant.py`)

- **Local engine does the maths.** For each question a compact JSON summary is built from the analysis (totals,
  protocol counts, top endpoints, HTTP transactions with frames and timings, TLS names, findings, plus facts about
  any frame number or IP mentioned in the question).
- **Sanitised.** The capture file, payloads, HTTP bodies, cookies, `Authorization` headers and URL query *values*
  are never included. You can preview the exact JSON on the AI Analyst page.
- **Consent.** Nothing is sent until you tick the consent box. Identical questions are served from a cache.
- **Structured output.** Gemini (official `google-genai` SDK) must return JSON: `answer`, `data_available`,
  and an `evidence` list of frame numbers / transaction IDs.
- **Validation.** Every reference is checked against the capture: the frame must exist, the transaction must
  exist, and a frame cited together with a transaction must belong to it. The details shown beside an answer
  (timestamp, addresses, summary, timing) are read from the **local analysis**, not from the model. Invalid
  references are removed and listed as *unverified*; frame/transaction numbers mentioned in the answer text that
  do not exist are flagged too.
- **Failures.** Missing key, invalid key, quota/rate limit (429), unknown model (404), server errors, timeouts,
  network errors, empty or non-JSON replies each produce a clear message, and the local engine answers instead.

---

## 4. Verifying results against Wireshark

1. Open the same file in Wireshark. Set **View → Time Display Format → Seconds Since First Captured Packet**
   (or *UTC Date and Time of Day* to compare absolute timestamps).
2. **Packet count / duration:** *Statistics → Capture File Properties*.
3. **A frame:** display filter `frame.number == N`; compare addresses, ports and info with the Packet Explorer.
4. **HTTP list:** filter `http`. Each request row shows *[Response in frame: N]* and each response
   *[Request in frame: N]* and *[Time since request]* (`http.time`) — compare with the request frame,
   response frame and response time columns.
5. **A connection:** filter `tcp.stream eq N` (the stream number is shown for every transaction).
6. **Protocols / endpoints:** *Statistics → Protocol Hierarchy* and *Statistics → Endpoints → IPv4*.
   Note that the protocol chart counts each packet once under its top protocol, like Wireshark's Protocol column.

If Wireshark's TCP preference *“Allow subdissector to reassemble TCP streams”* is turned off, Wireshark shows a
response on its **first** segment; compare with the *TTFB* column / “first response byte in frame” instead.

Known values of the bundled sample (`samples/sample_http.pcap`, regenerate with
`python -m tools.generate_sample_capture`): 123 packets, 4.5597 s, 13 HTTP transactions, 7 TCP streams,
2 TLS sessions; slowest transaction `T0007` = 1840.5 ms (frames 52 → 54); `T0011` and `T0012` have no response.

---

## 5. Automated tests

| File | Covers |
|---|---|
| `tests/test_parser.py` | PCAP and PCAPNG reading, identical results for both, frame numbering, timestamps, IPv4/IPv6/VLAN/ARP/ICMP/DNS, padding, empty / non-capture / truncated files, unsupported link type, packet limit, cross-check against Scapy's own dissection. |
| `tests/test_http.py` | GET, POST, field extraction, response time, segmentation, pipelining, retransmission, out-of-order, sequence wrap-around, interleaved connections, port reuse, missing response, reset, truncated body, mid-stream capture, gaps, chunked, HEAD, 100-continue, until-close, non-standard port, non-HTTP data. |
| `tests/test_tls.py` | HTTPS metadata (SNI, ALPN, version), split ClientHello, no HTTP transactions invented. |
| `tests/test_analytics.py` | Summary numbers, protocol distribution, traffic buckets, endpoints, filters, insights, empty capture. |
| `tests/test_ai.py` | Sanitised context, evidence validation, fabricated references, Gemini API errors, empty replies, missing credentials, disabled AI, `.env` loading, local answers in English and Hebrew. |
| `tests/test_app.py` | Every dashboard page renders for PCAP and PCAPNG; filters, slider, consent gate, Gemini answer path, caching, quota fallback. |

Test captures are **synthetic**: `tools/capture_builder.py` crafts packets with Scapy so every expected value is
known in advance. Gemini is replaced by a fake client in tests — no test contacts Google.

---

## 6. Known limitations

- **HTTP/1.0 and HTTP/1.1 only.** HTTP/2, HTTP/3 (QUIC) and anything inside TLS cannot be reconstructed.
- **No TLS decryption** (no key-log support).
- **IP fragments are not reassembled**; fragmented packets are labelled and skipped by the stream builder.
- **Timestamps** are stored as 64-bit floats: differences are accurate to about ±0.25 µs; nanosecond captures
  lose their last digits.
- **Port-based labels** (NTP, QUIC, …) are guesses and are marked as such.
- Captures limited by a short **snap length** lose payload bytes; the affected streams show gaps.
- Tunnels (GRE, VXLAN, …) are not unwrapped; 802.11 / other link types are counted but not decoded.
- Compressed bodies are not decompressed (bodies are measured, not displayed).
- Captures are held in memory (default limits: 300 MB upload, 500,000 frames).
- The local (non-AI) answer engine understands only a fixed set of question types.
- TCP stream numbers follow Wireshark's ordering idea but may differ in unusual cases (e.g. port reuse).

## 7. Project layout

```
app.py                     Streamlit entry point (navigation, upload, sidebar)
analyzer/                  analysis engine (no UI code)
  parser.py  tcp_reassembly.py  http_analyzer.py  analytics.py  ai_assistant.py  models.py  config.py
ui/                        dashboard pages, theme and charts
tools/                     synthetic capture builder + sample generator
samples/                   generated demo capture (pcap + pcapng)
tests/                     automated tests
docs/                      assignment checklist, AI verification and AI usage templates
```
