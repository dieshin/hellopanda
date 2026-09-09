# Feature completion and operation

The missing feature paths are implemented. This expands the workbench; it does **not** repair the failed classifier benchmark. The saved Random Forest remains a TCP-only research model with the previously reported poor transfer performance.

| Capability | Implemented behavior | Confidence / 100 | Verification and limits |
| --- | --- | ---: | --- |
| UDP, DNS and QUIC analysis | Bidirectional UDP streams, visible DNS request timestamps/names/counts, NXDOMAIN counts, TShark-observed QUIC version and visible SNI | 93 | Real ACBackdoor UDP/DNS and Wireshark QUIC captures; encrypted DNS/application payload visibility is not claimed. UDP/QUIC never receive the TCP ML score. |
| Rare destinations and similar flows | Observed-host prevalence and per-destination packet/byte consistency | 90 | Tests on real captures and explicit sample sufficiency checks. Thresholds remain exploratory, not calibrated C2 decisions. |
| DNS tunnelling indicators | Query count, unique names, name length and label entropy within actual query-time windows | 90 | Real query timestamps tested; strongest observed window shown per flow. First question per DNS message; this is a heuristic, not proof of tunnelling. |
| Threat-intelligence providers | VirusTotal IP reports, AbuseIPDB checks, URLhaus host queries, GreyNoise Community IPv4 queries | 85 | Official request/response contracts and errors tested with mocked HTTP. Actual account credentials were not supplied, so live account compatibility/quotas remain unverified. |
| Hosting/shared infrastructure | Refresh published Cloudflare and AWS network ranges; match destination addresses locally | 92 | Live refresh succeeded with 11,008 ranges. Cloudflare ranges mark shared infrastructure; AWS ownership alone does not establish shared tenancy. No range match is unknown. |
| Authentication/authorization | Named bearer tokens with admin, analyst, viewer and sensor roles; remote TLS requirement, browser sign-in/sign-out, write audit | 90 | API and Chromium role tests pass. Requires deployment configuration, strong unique tokens and a trusted TLS proxy. This is token-based access, not SSO/MFA/user provisioning. |
| Live capture | Admin-only bounded dumpcap capture on configured interfaces, followed by existing import and analysis | 94 | User-executed sudo loopback test passed: 61 generated test packets captured and 3 flows processed. Disabled-interface, failure cleanup and command boundaries covered. Non-root service-account permissions and other interfaces remain unverified. Single-process concurrency guard. |
| SIEM and endpoint integration | Splunk HEC or HTTPS NDJSON forwarding, NDJSON export, authenticated event ingestion, ECS/Wazuh import and tuple/time correlation | 86 | Receiver acknowledgement and ingestion/correlation tested. A real SIEM/EDR deployment was not supplied. Receiver acceptance is not proof of indexing. |
| Dashboard integration | Connections page, role-aware controls, protocol filters, per-finding SIEM forwarding, context refresh and capture controls | 94 | Chromium sign-in/out, viewer/admin restrictions, UDP/QUIC uploads, evidence view and mobile layout pass. |

Confidence scores are engineering judgments, not model probabilities. The priority remaining research task is useful independently measured detection performance; historical C2 benchmark results are preserved in `MODEL_REPORT.md` and `../../datasets/training/evaluation.json`.

## Defaults and configuration

Start the server with `python run.py`; open `http://127.0.0.1:8000/#integrations` for **Connections**. The existing prepared environment can run it with `/tmp/hellopanda-analyst-venv/bin/python run.py` from this application directory.

Exploratory behaviour rules and hosting-range matching are enabled. Threat-intelligence requests, live capture, SIEM forwarding and AI remain disabled until their configuration is supplied. Risk fusion still uses its explicit required-component policy and stays disabled by default; enabling it will not fill missing components with zero. None of these switches improves classifier accuracy.

`config/detection.yaml` owns all heuristic thresholds. Rare-destination scoring requires at least ten observed source hosts. Similar-flow scoring requires five usable connections. DNS defaults require at least 30 queries and 20 unique names within 300 seconds, a name of at least 60 characters, and maximum label entropy of at least 3.5. Each criterion is a measured clue, not an independently validated malicious label. Existing periodicity and benign-baseline ratio detectors remain available.

Protocol extraction uses TShark TCP/UDP stream IDs and keeps first-observed direction and wire-byte semantics. QUIC requires actual dissector evidence; UDP port 443 alone is not classified as QUIC. QUIC connection migration across UDP streams is not reconstructed. A trained TCP model remains ineligible for non-TCP feature contracts. Reimport an older capture to obtain the new metadata columns; preserved old evidence is not rewritten.

## Threat intelligence and hosting context

Set `threat_intelligence.enabled: true` in `config/providers.yaml` and set the appropriate environment variables in `.env`:

- `VIRUSTOTAL_API_KEY`
- `ABUSEIPDB_API_KEY`
- `URLHAUS_AUTH_KEY`
- `GREYNOISE_API_KEY`

Provider switches can be disabled independently. The clients query IP/host reputation only; they do not submit malware, download payloads, or contact destinations found in captures. Private/non-global IPs are not sent. GreyNoise Community IPv6 is explicitly unsupported. URLhaus uses the currently documented bulk lookup API `/v1/host/` with the `Auth-Key` header; the separate feed download API has a different version.

The default global budget is twelve provider requests per analysis, with a ten-second timeout, bounded response bodies and one-hour caching of successful observations/no-record responses. There are no automatic retries. Missing keys, malformed replies, 404/no-record, 429/rate limits, network errors and exhausted budgets remain explicit unknown states. Successful zero-report checks are provider observations, not benign labels.

Use **Refresh hosting ranges** to download the public Cloudflare IPv4/IPv6 and AWS feeds. The refresh is saved only after all feeds parse successfully; failed refreshes retain the previous snapshot. Snapshots older than seven days are not used. Reanalyse a dataset after refreshing context.

A match means published network ownership, not origin ownership or malware attribution. Where shared infrastructure is established by the configured feed classification, reputation contribution is capped at 30/100 by default; original provider scores remain in evidence. Current IP reputation does not establish the reputation of an address when a historical capture was collected.

## Authenticated deployment

`config/integrations.yaml` contains `auth`, `live_capture`, `endpoint` and `siem` settings. Local loopback mode does not require a token. Before exposing the app beyond loopback, enable `auth.enabled`, set at least one administrator token, and configure the deployment hostname in `app.allowed_hosts`.

Generate each token independently with `python -c 'import secrets; print(secrets.token_urlsafe(32))'` in your own terminal. Set `PANDA_ADMIN_TOKEN`, `PANDA_ANALYST_TOKEN`, `PANDA_VIEWER_TOKEN` and/or `PANDA_SENSOR_TOKEN` in the server environment. Do not reuse tokens across roles. Configuration stores environment variable names, never token values. Removing/rotating an environment token revokes its access on the next request after the process environment is updated/restarted.

| Role | Permission |
| --- | --- |
| Viewer | Read evidence/status and export findings |
| Analyst | Viewer access plus upload, analyse, investigate and forward to configured SIEM |
| Admin | Analyst access plus training, hosting refresh, live capture and configuration review |
| Sensor | Submit endpoint events only |

API clients use `Authorization: Bearer <token>`. The browser keeps its token only in tab memory; reload/sign-out clears it. Remote authenticated access requires HTTPS. Use a TLS reverse proxy with controlled forwarded headers; configure Uvicorn trusted proxy addresses for that deployment. Never trust arbitrary client-supplied forwarded headers. Secrets are not URL parameters, browser storage values or configuration API output.

Successful authorized writes are audited with actor, role, route, method and HTTP result; the audit does not store bearer tokens or request bodies. API authentication failure responses and server access logs cover rejected requests separately. The application remains a single-process SQLite service with bounded operations; it has not undergone a production penetration test and does not implement distributed queues or SSO/MFA.

## Live capture

Enable `live_capture.enabled` and populate the explicit interface allowlist. Then use **Connections → Capture and analyse**, or `POST /api/capture` with `{"interface":"YOUR_CONFIGURED_INTERFACE","seconds":10}`. Only an administrator can start captures when authentication is enabled.

The host must provide `dumpcap` and its normal capture permissions. The app never invokes sudo, changes capabilities or accepts arbitrary capture command arguments. Defaults cap the operation at 60 seconds, 100,000 packets and 16 MiB; the configured limits must fit the importer limits. An invalid interface, nonzero exit or timeout rejects partial results. Only one capture runs at a time in the app process. Do not run multiple workers for live capture without a shared job coordinator.

The user successfully ran the native loopback test with sudo: 61 generated test packets were captured and 3 extracted flows were processed. The isolated test had no trained model and produced no findings, which is valid for traffic without sufficient scoring evidence. This verifies the tested host under sudo; permissions for the normal application service account, other interfaces and other operating systems remain unverified. See `TEST_REPORT.md` for the recorded result.

## Endpoint evidence and SIEM

A sensor submits `POST /api/endpoint-events` with an `events` array. Each event requires `event_id`, timezone-aware `timestamp`, `host`, `source`, `src_ip`, `dst_ip`, `src_port`, `dst_port`, `protocol` (`tcp` or `udp`) and `process_name`. Optional fields are `process_id` and `process_hash`. Batches are validated before atomic persistence; repeated unchanged IDs are idempotent, while conflicting reuse rejects the entire batch.

For actual exported telemetry:

```sh
python scripts/import_endpoint_events.py exported-events.jsonl --format ecs
python scripts/import_endpoint_events.py wazuh-alerts.jsonl --format wazuh
```

The importer reads `PANDA_SENSOR_TOKEN`; `--token-env` and `--base-url` are configurable. Remote endpoints require HTTPS. ECS expects nested standard `event`, `host`, `source`, `destination`, `network` and `process` objects. Wazuh expects `data.win.system` / `data.win.eventdata` Sysmon Event ID 3 and skips other event IDs. Adapt upstream exports to these documented schemas rather than invent process evidence. The importer streams one event per request; on an error it stops and reports the line, preserving earlier accepted events.

Reanalyse captures after ingestion. Correlation uses the directed five-tuple and the observed flow start/end interval with a configurable five-second tolerance. It reports sensor attribution and does not prove malicious execution; NAT, clock skew, reused tuples and missing endpoint telemetry can prevent or confuse matches. Process names/paths are not automatically included in LLM requests.

Configure `siem.enabled`, `siem.url`, `siem.format` (`splunk_hec` or `ndjson`) and `SIEM_TOKEN`. Splunk expects an HTTPS HEC event URL such as the deployment's `/services/collector/event` endpoint. The browser forwards an explicitly selected reviewed finding. The API accepts selected IDs at `POST /api/siem/send`; `POST /api/exports` downloads NDJSON without sending it externally. Exports contain connection identifiers, evidence and any correlated endpoint metadata, so configure the receiver appropriately.

SIEM requests do not follow redirects or automatically retry. Splunk requires its success code `0`; other configured NDJSON receivers require a successful HTTP status. An HTTP acknowledgement is not independently verified indexing. Repeated submissions may duplicate events; exported stable event IDs support receiver deduplication. A failed/unconfirmed request is reported rather than saved as a successful delivery.

## Verification and sources

The latest run has 50 passing tests and no skips, including the optional tabular test against the existing real corpus. It includes real packet decoding and explicit HTTP/endpoint contract fixtures; mocked reputation values are never saved as real corpus labels or benchmark observations. Ruff and JavaScript syntax checks pass. Chromium verified training, login/logout, role controls, automatic UDP/QUIC upload, pagination, protocol filtering, evidence display and mobile layout without application JavaScript errors. See [TEST_REPORT.md](TEST_REPORT.md) for fresh results, response-validation fixes and remaining live-service checks.

Source references:

- VirusTotal IP report: https://docs.virustotal.com/reference/ip-info
- AbuseIPDB check: https://docs.abuseipdb.com/
- URLhaus bulk host lookup: https://urlhaus-api.abuse.ch/
- GreyNoise Community API: https://docs.greynoise.io/reference/community
- Cloudflare ranges: https://www.cloudflare.com/ips/
- AWS ranges: https://docs.aws.amazon.com/vpc/latest/userguide/aws-ip-ranges.html
- Splunk HEC: https://help.splunk.com/en?resourceId=Splunk_Data_UsetheHTTPEventCollector&version=splunk-9_4
- QUIC validation capture: Wireshark `test/captures/quic-double-retry.pcapng.gz`; URL, source Git blob and SHA-256 hashes retained in `../../datasets/validation/manifest.json`. This capture is only for protocol regression, never model training.
