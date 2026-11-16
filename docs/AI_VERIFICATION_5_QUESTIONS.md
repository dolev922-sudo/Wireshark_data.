# AI verification — five questions

Purpose: show that the AI Analyst's answers were checked against an independent source (Wireshark).

**How to fill this in**

1. Load your capture, open **AI Analyst**, tick the consent box, choose **Gemini**.
2. Ask each question. Use **Download Q&A log (Markdown)** to keep the exact answers and evidence.
3. For every answer, check the cited frames / transactions in Wireshark (README §4) and record the result.

| Field | Value |
|---|---|
| Capture file name | |
| Capture SHA-256 (Overview → Capture summary / Q&A log) | |
| Date | |
| Gemini model | |
| Wireshark version | |

---

## Question 1

- **Question asked:**
- **AI answer (copy):**
- **Evidence shown by the dashboard** (frame numbers / transaction IDs / timestamps):
- **Wireshark check** (filter used, what you saw):
- **Result:** ☐ Correct ☐ Partly correct ☐ Wrong ☐ AI said the data is not available
- **Notes:**

## Question 2

- **Question asked:**
- **AI answer (copy):**
- **Evidence shown by the dashboard:**
- **Wireshark check:**
- **Result:** ☐ Correct ☐ Partly correct ☐ Wrong ☐ AI said the data is not available
- **Notes:**

## Question 3

- **Question asked:**
- **AI answer (copy):**
- **Evidence shown by the dashboard:**
- **Wireshark check:**
- **Result:** ☐ Correct ☐ Partly correct ☐ Wrong ☐ AI said the data is not available
- **Notes:**

## Question 4

- **Question asked:**
- **AI answer (copy):**
- **Evidence shown by the dashboard:**
- **Wireshark check:**
- **Result:** ☐ Correct ☐ Partly correct ☐ Wrong ☐ AI said the data is not available
- **Notes:**

## Question 5

- **Question asked:**
- **AI answer (copy):**
- **Evidence shown by the dashboard:**
- **Wireshark check:**
- **Result:** ☐ Correct ☐ Partly correct ☐ Wrong ☐ AI said the data is not available
- **Notes:**

---

## Suggested questions (pick five, mix easy and hard)

| Question | What to check in Wireshark |
|---|---|
| How many packets are in the capture and how long is it? | Statistics → Capture File Properties |
| Which HTTP request had the longest response time? | Filter `http`, column `http.time` (Time since request) |
| Which request received status 404 / 500? | Filter `http.response.code >= 400`, then *[Request in frame]* |
| Which requests did not receive a response? | Filter `http.request && !http.response_in` |
| What happened in frame N? | Filter `frame.number == N` |
| Which hosts were contacted over HTTP? | Statistics → HTTP → Requests |
| What was the content of the HTTPS page? *(trap: must answer "not available")* | TLS is encrypted — nothing to see |
| באיזו כתובת IP נשלחו הכי הרבה חבילות? | Statistics → Endpoints → IPv4 |

## Summary

| | Count |
|---|---|
| Correct | /5 |
| Partly correct | /5 |
| Wrong | /5 |
| References removed by the validator as unverified | |

**Conclusion (2–3 sentences):**
