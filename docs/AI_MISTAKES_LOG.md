# AI mistakes and corrections log

Record every case where an AI tool (the code assistant used to build the project, or Gemini inside the
dashboard) produced something wrong, how you noticed, and how it was corrected.

## Entry template

| Field | Value |
|---|---|
| # | |
| Date | |
| AI tool | ☐ Code assistant (development) ☐ Gemini (AI Analyst page) |
| What was asked | |
| What the AI produced | |
| Why it was wrong | |
| How the mistake was detected | (Wireshark comparison / failing test / evidence validator / manual review) |
| Correction | |
| How the correction was verified | |

---

## Mistakes found and fixed while the project was being built

These are real, taken from the development session; each was caught by running the code, not by reading it.

| # | What was wrong | How it was detected | Correction | Verified by |
|---|---|---|---|---|
| 1 | The first test expectations assumed the synthetic capture had 16 packets and lasted 0.1955 s; it actually has 15 packets and lasts 0.192 s. | 7 parser tests failed on the first run. | Recounted the generated packets and delays by hand and corrected the expected values (the engine was right, the hand count was wrong). | `tests/test_parser.py` passes. |
| 2 | A truncated PCAPNG file produced no warning: the reader silently stopped at the damaged block. | `test_truncated_pcapng_keeps_earlier_frames` failed. | Added `_pcapng_is_truncated`, which walks the block chain and checks that the file ends exactly on a block boundary. | Same test; truncated upload in the browser shows the warning. |
| 3 | The Packet Explorer's "Protocol layers" panel showed only `Raw` bytes instead of Ethernet / IP / TCP layers. | Seen in a browser screenshot of the running app. | Scapy registers link types only when its layer modules are imported; added the imports in `ui/page_packets.py`. | `test_frame_dissection_shows_real_layers`. |
| 4 | One test left `SLOW_THRESHOLD_MS=250` in the process environment, which changed the result of an unrelated dashboard test depending on test order. | A test passed alone but failed in the full run. | The test now restores the environment itself in a `finally` block. | Full suite passes in one run. |
| 5 | The protocol chart's largest value label was cut off; the suggested questions were clipped into one scrolling row; table headers were truncated. | Browser screenshots. | Added axis headroom, replaced the pill row with a two-column button grid, shortened column titles. | New screenshots. |

## Your entries

Add your own entries below (at least one Gemini answer you had to correct or that the validator rejected).
