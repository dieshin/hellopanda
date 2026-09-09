# Test results — 9 September 2026

The current implementation passes **50 automated tests**, with no skips, plus Chromium, local HTTP workflow checks and a user-executed native loopback capture test. Testing reproduced and fixed two response-validation defects: malformed VirusTotal statistics raised an unhandled exception, and Splunk acknowledgement validation both crashed on non-object JSON and incorrectly accepted boolean `false` as numeric success code `0`.

## Results

Confidence scores describe confidence in the stated result, not malware probabilities or production readiness.

| Area | Result and evidence | Confidence / 100 |
| --- | --- | ---: |
| Automated functional suite | 50 passed in 8.90 seconds. Includes real PCAP extraction, training, provenance/tamper checks, evidence citations, access rules, integration contracts and failure cases. The optional dataset test ran against the existing labelled corpus. | 98 |
| Static checks and environment | Ruff and JavaScript syntax passed; all 42 installed package versions match `requirements.lock.txt`. | 99 |
| Browser workflows | Headless system Chromium: authenticated model training; ACBackdoor upload/analysis (47 flows); QUIC upload/analysis (1 flow); pagination; QUIC filtering and evidence; disabled capture/SIEM controls; viewer write restrictions; sign-out/reload token clearing; no browser storage tokens; 390px layout without horizontal overflow; no application JavaScript errors. | 95 |
| Real local HTTP and importer CLIs | Admin/analyst/viewer/sensor permission checks; TCP-only ML scoring; deduplicated NDJSON export; malformed and truncated PCAP rejection with file cleanup; ECS and Wazuh CLI ingestion; endpoint evidence after reanalysis; cache invalidation and subsequent reuse. Process identities were explicitly marked test fixtures. | 95 |
| Hosting context | Live Cloudflare/AWS refresh returned 11,008 ranges at `2026-09-09T06:04:34.107692+00:00`. Mocked failed-refresh test confirmed the previous snapshot is preserved. | 94 |
| Threat-intelligence and SIEM contracts | Mocked provider replies, error statuses, malformed replies, caching, private-address handling, shared-infrastructure cap and Splunk acknowledgement checks pass. No live account or SIEM deployment was tested. | 87 |
| Live capture | User-reported privileged loopback test passed: 61 generated test packets captured, 3 flows processed, 0 findings, 3 unmeasured records and 0 ML-scored records. Mocked failure/timeout tests also confirm partial-file cleanup and lock release. The native result covers this host under sudo; capture from the normal application service account remains unverified. | 94 |
| Model benchmark | Fresh isolated training reproduced **0/101 held-out C2 detections** and **5/539 normal-flow false positives (0.93%)**. The classifier is not suitable for reliable C2 detection on this evidence. | 99 |

## Reproduce

From this application directory:

```sh
PYTHONDONTWRITEBYTECODE=1 HELLO_PANDA_DATASET='../../datasets/training/labelled-flows.csv' /tmp/hellopanda-analyst-venv/bin/python -m pytest -q -p no:cacheprovider
/tmp/hellopanda-analyst-venv/bin/python -m ruff check --no-cache backend scripts tests run.py
node --check frontend/app.js
```

FastAPI tests require local thread/socket access. One upstream Starlette warning concerns the deprecated AnyIO `BlockingPortal` alias; it did not fail the tests.

One-time browser/server/API harnesses are retained as `/tmp/hellopanda-testing-{server,browser,api}.py`; the browser continuation assumes the two captures have already been imported. Screenshots are `/tmp/hellopanda-testing-evidence.png` and `/tmp/hellopanda-testing-mobile.png`. The browser harness initially assumed 25 rows per page; the isolated test configuration was set to 25 to exercise pagination. The application default remains 100.

Tests used temporary databases, uploads and model artifacts. The existing application database, corpus labels and saved production-workspace model were not changed.

## Remaining verification

- Native loopback capture is verified by the user-provided successful output from `sudo /tmp/hellopanda-test-live-capture.sh`. Artifacts: `/tmp/hellopanda-live-check-wvn9u_hv`. The script confirmed the generated UDP tuple in the extracted records, positive packet counts, complete processed-record accounting and saved analysis completion. Zero findings is valid: the isolated workspace had no trained model and the enabled rules produced no evidence for these flows. The initial script incorrectly required a finding; its assertion was corrected before this successful run. The assistant has not independently read the root-owned artifacts. Capture permissions for a non-root service account and non-loopback interfaces remain unverified.
- Live VirusTotal, AbuseIPDB, URLhaus, GreyNoise, SIEM indexing and customer EDR exports remain unverified. Contract fixtures establish application behavior, not real account compatibility.
- No live paid/local LLM comparison was run. Citation/schema tests do not establish equivalent analytical accuracy across models.
- Only Linux and system Chromium were exercised. Production TLS proxy deployment, other browsers/operating systems, sustained load and multi-process behavior were not tested.
- Improve and independently evaluate classifier generalization before relying on its scores. The normal holdout shares the CTU capture with training, and external C2 labels are source-attributed. No useful detection accuracy is inferred from passing software tests.
