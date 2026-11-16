"""HTTP Transactions page: request/response table, filters, details and stream explanation."""

from __future__ import annotations

import pandas as pd
import streamlit as st

from analyzer import analytics
from analyzer.models import HttpMessage, HttpTransaction

from . import charts, theme
from .state import Bundle, go_to, parse_port

SENSITIVE_HEADERS = {"authorization", "proxy-authorization", "cookie", "set-cookie", "x-api-key", "x-auth-token"}
STATE_TONES = {"Complete": "good", "Uncertain match": "warning", "Incomplete": "warning",
               "No response": "serious", "Orphan response": "neutral"}

TRANSACTION_COLUMNS = {
    "id": st.column_config.TextColumn("ID", width="small"),
    "method": st.column_config.TextColumn("Method", width="small"),
    "host": "Host",
    "uri": st.column_config.TextColumn("URI", width="medium"),
    "status": st.column_config.NumberColumn("Status", format="%d", width="small"),
    "state": st.column_config.TextColumn("State", width="small"),
    "request_frame": st.column_config.NumberColumn("Req frame", format="%d"),
    "response_frame": st.column_config.NumberColumn("Resp frame", format="%d",
                                                    help="Frame that completes the response (where Wireshark shows it)."),
    "request_time": st.column_config.NumberColumn("Req at (s)", format="%.6f"),
    "response_at": st.column_config.NumberColumn("Resp at (s)", format="%.6f"),
    "response_time_ms": st.column_config.NumberColumn("Resp time (ms)", format="%.3f",
                                                      help="Response frame time minus request frame time (Wireshark http.time)."),
    "ttfb_ms": st.column_config.NumberColumn("TTFB (ms)", format="%.3f",
                                             help="Time until the first frame of the response."),
    "client_ip": "Client IP", "client_port": st.column_config.NumberColumn("Client port", format="%d", width="small"),
    "server_ip": "Server IP", "server_port": st.column_config.NumberColumn("Server port", format="%d", width="small"),
    "stream": st.column_config.NumberColumn("TCP stream", format="%d", width="small"),
}
TABLE_ORDER = ["id", "method", "host", "uri", "status", "state", "request_frame", "response_frame", "request_time",
               "response_at", "response_time_ms", "ttfb_ms", "client_ip", "client_port", "server_ip", "server_port", "stream"]


def transaction_filters(transactions: pd.DataFrame, prefix: str) -> pd.DataFrame:
    """Render the HTTP filter controls and return the filtered table."""
    with st.container(border=True):
        row1 = st.columns([2.4, 1.4, 2, 1.6, 1.6])
        search = row1[0].text_input("Search host / URI / ID", key=f"{prefix}_search", placeholder="e.g. /login or T0003")
        methods = row1[1].multiselect("Method", sorted(m for m in transactions["method"].unique() if m), key=f"{prefix}_methods")
        hosts = row1[2].multiselect("Host", sorted(h for h in transactions["host"].unique() if h), key=f"{prefix}_hosts")
        codes = sorted(int(c) for c in transactions["status"].dropna().unique())
        status_codes = row1[3].multiselect("Status code", codes, key=f"{prefix}_codes")
        states = row1[4].multiselect("State", sorted(transactions["state"].unique()), key=f"{prefix}_states")
        row2 = st.columns([2, 1.2, 3])
        ip = row2[0].text_input("IP address (client or server)", key=f"{prefix}_ip", placeholder="e.g. 203.0.113.10")
        port_text = row2[1].text_input("Port", key=f"{prefix}_port", placeholder="e.g. 80")
        times = transactions["response_time_ms"].dropna()
        time_range = None
        if len(times) and times.max() > times.min():
            low, high = float(times.min()), float(times.max())
            chosen = row2[2].slider("Response time range (ms)", low, high, (low, high), key=f"{prefix}_rt", format="%.1f")
            if chosen != (low, high):
                time_range = chosen
    port, port_error = parse_port(port_text)
    if port_error:
        st.error(port_error)
    return analytics.filter_transactions(
        transactions, methods=methods, hosts=hosts, status_codes=status_codes, states=states, ip=ip, port=port,
        response_time_ms=time_range, search=search)


def render(bundle: Bundle) -> None:
    transactions = bundle.transactions
    theme.page_header("HTTP Transactions", "Requests matched to their responses by position inside each TCP stream.")
    if transactions.empty:
        st.info("No unencrypted HTTP/1.x traffic was found in this capture.", icon=":material/info:")
        if len(bundle.tls):
            st.markdown("The capture does contain **encrypted TLS/HTTPS** connections. Their HTTP content cannot be "
                        "read without the session keys, so only handshake metadata is available:")
            render_tls_table(bundle)
        return

    answered = transactions["response_time_ms"].dropna()
    stats = analytics.response_time_statistics(transactions)
    theme.kpi_row([
        ("Transactions", f"{len(transactions):,}", f"{len(answered):,} with a measured response time"),
        ("Median response time", theme.format_ms(stats.get("median")), f"mean {theme.format_ms(stats.get('mean'))}"),
        ("Slowest response", theme.format_ms(stats.get("max")), f"95th percentile {theme.format_ms(stats.get('p95'))}"),
        ("Error responses", f"{int((transactions['status'] >= 400).sum()):,}", "status 4xx or 5xx"),
        ("Without response", f"{int((transactions['state'] == 'No response').sum()):,}", "request captured, no answer"),
    ])

    theme.section("Filters")
    filtered = transaction_filters(transactions, "http")
    st.markdown(f"Showing **{len(filtered):,}** of {len(transactions):,} transactions. Click a column header to sort; "
                "select a row for details.")
    event = st.dataframe(filtered[TABLE_ORDER], hide_index=True, height=360, on_select="rerun",
                         selection_mode="single-row", key="http_table", column_config=TRANSACTION_COLUMNS)
    st.download_button("Download filtered transactions (CSV)", filtered.to_csv(index=False),
                       file_name="http_transactions.csv", mime="text/csv", icon=":material/download:")

    selected_rows = event.selection.rows if event and event.selection else []
    if selected_rows and selected_rows[0] < len(filtered):
        transaction = bundle.analysis.transaction(filtered.iloc[selected_rows[0]]["id"])
        render_transaction(bundle, transaction, filtered.iloc[selected_rows[0]]["state"])
    else:
        st.caption("No transaction selected.")

    if len(bundle.tls):
        theme.section("Encrypted HTTPS / TLS sessions (metadata only)")
        st.caption("HTTP inside TLS is encrypted. The analyzer reports the handshake metadata it can see and does not "
                   "guess methods, URIs or status codes.")
        render_tls_table(bundle)


def render_tls_table(bundle: Bundle) -> None:
    st.dataframe(bundle.tls, hide_index=True, column_config={
        "stream": st.column_config.NumberColumn("TCP stream", format="%d", width="small"),
        "server_name": "Server name (SNI)", "client": "Client", "server": "Server", "tls_version": "TLS version",
        "alpn": "ALPN offered",
        "client_hello_frame": st.column_config.NumberColumn("Client Hello frame", format="%d"),
        "server_hello_frame": st.column_config.NumberColumn("Server Hello frame", format="%d"),
        "handshake_ms": st.column_config.NumberColumn("Hello → Hello (ms)", format="%.3f"),
        "bytes": st.column_config.NumberColumn("TLS bytes", format="localized")})


def _headers_table(message: HttpMessage, reveal: bool) -> pd.DataFrame:
    rows = []
    for name, value in message.headers:
        if name.lower() in SENSITIVE_HEADERS and not reveal:
            value = f"•••• hidden ({len(value)} characters)"
        rows.append({"Header": name, "Value": value})
    return pd.DataFrame(rows, columns=["Header", "Value"])


def _message_block(title: str, message: HttpMessage, reveal: bool, start: float) -> None:
    st.markdown(f"**{title}**")
    st.code(message.start_line, language=None)
    frames = ", ".join(str(frame) for frame in message.frames[:12]) + ("…" if len(message.frames) > 12 else "")
    body = f"{message.body_length:,} bytes" + (f" of {message.declared_length:,} declared" if message.declared_length is not None
                                              and message.declared_length != message.body_length else "")
    theme.key_values([
        ("Frames", frames),
        ("First byte", f"frame {message.first_frame} at {message.first_timestamp - start:.6f} s"),
        ("Complete in", f"frame {message.last_frame} at {message.last_timestamp - start:.6f} s"),
        ("Timestamp", theme.format_timestamp(message.last_timestamp)),
        ("Body", f"{body} · framing: {message.framing}"),
    ])
    st.dataframe(_headers_table(message, reveal), hide_index=True, height=min(38 * (len(message.headers) + 1) + 4, 300))


def render_transaction(bundle: Bundle, transaction: HttpTransaction, state: str) -> None:
    analysis = bundle.analysis
    start = analysis.start_time or 0.0
    stream = analysis.stream(transaction.stream_id)
    title = (f"{transaction.method} {transaction.host}{transaction.uri}" if transaction.request
             else "Response without a captured request")
    theme.section(f"Transaction {transaction.transaction_id}")
    badges = theme.badge(state, STATE_TONES.get(state, "neutral"))
    if transaction.status_code is not None:
        badges += " " + theme.badge(f"HTTP {transaction.status_code}", theme.status_tone(transaction.status_code))
    st.markdown(f'{badges} &nbsp; <span class="nta-mono">{theme.esc(title[:200])}</span>', unsafe_allow_html=True)
    for warning in transaction.warnings:
        st.warning(warning, icon=":material/warning:")

    theme.kpi_row([
        ("Response time", theme.format_ms(transaction.response_time * 1000 if transaction.response_time is not None else None),
         "request frame → frame completing the response"),
        ("Time to first byte", theme.format_ms(transaction.time_to_first_byte * 1000 if transaction.time_to_first_byte is not None else None),
         "request frame → first response frame"),
        ("Request frame", str(transaction.request_frame or "-"), "frame.number in Wireshark"),
        ("Response frame", str(transaction.response_frame or "-"),
         f"first response byte in frame {transaction.response_first_frame}" if transaction.response else "not captured"),
        ("TCP stream", str(transaction.stream_id),
         f"{transaction.client_ip}:{transaction.client_port} → {transaction.server_ip}:{transaction.server_port}"),
    ])
    if transaction.request and transaction.response and transaction.response_time and transaction.response_time > 0:
        st.plotly_chart(charts.transaction_timeline(
            transaction.request.last_timestamp, transaction.response.first_timestamp, transaction.response.last_timestamp),
            config=charts.PLOT_CONFIG, key="http_timeline")

    reveal = st.toggle("Reveal sensitive header values (Authorization, Cookie…) — shown only on this computer",
                       key="http_reveal")
    left, right = st.columns(2, gap="large")
    with left:
        if transaction.request:
            _message_block("Request", transaction.request, reveal, start)
        else:
            st.info("The request was not captured.")
    with right:
        if transaction.response:
            for extra in transaction.informational:
                st.caption(f"Interim response before the final one: {extra.start_line} (frame {extra.first_frame})")
            _message_block("Response", transaction.response, reveal, start)
        else:
            st.info("No response was captured for this request.")

    theme.section("How this exchange was reconstructed")
    theme.steps(_explanation(transaction, stream, start))
    st.caption(f"Verify in Wireshark with the display filter `tcp.stream eq {transaction.stream_id} && http`, or "
               f"`frame.number == {transaction.request_frame or transaction.response_first_frame}`.")
    if st.button(f"Open TCP stream {transaction.stream_id} in Packet Explorer", icon=":material/table_rows:",
                 key="http_open_stream"):
        go_to("packets", px_stream=str(transaction.stream_id), px_search="", px_ip="", px_port="", px_protocols=[],
              px_issues=False)


def _explanation(transaction: HttpTransaction, stream, start: float) -> list[str]:
    """Plain-language walk through of the stream, built only from measured facts."""
    esc = theme.esc
    items = []
    client, server = stream.client, stream.server
    if stream.handshake_complete:
        items.append(f"<b>TCP connection.</b> {esc(stream.label())} was opened with a three-way handshake "
                     f"(SYN in frame {client.syn_frame}, SYN-ACK in frame {server.syn_frame}). It is TCP stream "
                     f"{stream.stream_id}, containing {len(stream.frames)} frames.")
    else:
        items.append(f"<b>TCP connection.</b> {esc(stream.label())} is TCP stream {stream.stream_id} "
                     f"({len(stream.frames)} frames). Its handshake was not (fully) captured, so the start of the "
                     "conversation may be missing.")
    notes = []
    if stream.retransmissions:
        notes.append(f"{stream.retransmissions} retransmitted segment(s) were ignored (the first copy is used)")
    if stream.out_of_order:
        notes.append(f"{stream.out_of_order} out-of-order segment(s) were moved back into sequence")
    if stream.has_gaps:
        notes.append(f"{client.gap_bytes + server.gap_bytes:,} bytes are missing from the capture")
    items.append("<b>Reassembly.</b> The payload bytes of each direction were ordered by TCP sequence number"
                 + ("; " + "; ".join(notes) if notes else "; no retransmissions, reordering or gaps were found") + ".")
    request, response = transaction.request, transaction.response
    if request:
        where = (f"frame {request.first_frame}" if len(request.frames) == 1
                 else f"{len(request.frames)} TCP segments (frames {request.first_frame}–{request.last_frame})")
        items.append(f"<b>Request.</b> <span class='nta-mono'>{esc(request.start_line[:160])}</span> was found in {where}. "
                     f"It is request number {transaction.index_in_stream} on this connection and is complete at "
                     f"{request.last_timestamp - start:.6f} s.")
    if response:
        where = (f"frame {response.first_frame}" if len(response.frames) == 1
                 else f"{len(response.frames)} TCP segments (frames {response.first_frame}–{response.last_frame})")
        framing = {"content-length": "its Content-Length header", "chunked": "chunked transfer encoding",
                   "until-close": "the connection close", "none": "the header block (no body)"}[response.framing]
        items.append(f"<b>Response.</b> <span class='nta-mono'>{esc(response.start_line[:160])}</span> was found in {where}. "
                     f"Its end was determined from {framing}.")
    if request and response:
        certainty = ("The stream has no missing bytes before this exchange, so the pairing is certain."
                     if transaction.match_confidence == "confirmed" else
                     "Bytes are missing from this stream, so the pairing is marked uncertain.")
        items.append(f"<b>Matching.</b> HTTP/1.x answers requests in order on a connection, so response number "
                     f"{transaction.index_in_stream} belongs to request number {transaction.index_in_stream}. "
                     f"Time proximity is not used. {certainty}")
        items.append(f"<b>Response time.</b> {response.last_timestamp - start:.6f} s (frame {response.last_frame}) "
                     f"− {request.last_timestamp - start:.6f} s (frame {request.last_frame}) = "
                     f"<b>{transaction.response_time * 1000:.3f} ms</b>.")
    elif request:
        items.append("<b>Matching.</b> No later response exists in the server→client byte stream of this "
                     "connection, so the request is reported as unanswered and no response time is given.")
    else:
        items.append("<b>Matching.</b> This response appears before any captured request on the connection, so it "
                     "cannot be paired and no response time is given.")
    return items
