# Hello Panda

A local TCP/UDP network-evidence workbench with a Python/FastAPI backend, a browser dashboard, configurable behavioural analysis, and a separate, provider-configurable AI analyst layer.

**Status: working local network research prototype; not a reliable general C2 detector.** A real Random Forest has been trained and saved. Its first external test detected **0/101** source-attributed C2 streams; it flagged **5/539 (0.93%)** held-out normal streams. These separate tests do not establish deployment accuracy. See [MODEL_REPORT.md](MODEL_REPORT.md) for labels, methodology, measured results and remaining work.

See [FEATURES.md](FEATURES.md) for the implemented DNS/QUIC and behaviour checks, four threat-intelligence clients, hosting context, authentication, live capture, endpoint ingestion and SIEM forwarding, including configuration and validation limits.

## Run locally

Python 3.12+ and TShark must be installed. From this application directory:

```sh
python -m venv .venv
.venv/bin/python -m pip install -r requirements.lock.txt
.venv/bin/python run.py
```

In this workspace, the prepared environment is available now:

```sh
/tmp/hellopanda-analyst-venv/bin/python run.py
```

Open <http://127.0.0.1:8000>. FastAPI serves the dashboard directly. On Windows, use `.venv\Scripts\python.exe`; put Wireshark's TShark executable on PATH. Windows packet extraction has not been tested. Local `var/` must be writable for SQLite journals, uploads and model artifacts.

The default binds to loopback. The default is local access mode. Scoped token authentication is available for deployment; there is no distributed job queue. External enrichment and LLM requests remain disabled by default. No GPU is needed for the Random Forest. Model artifacts are locally generated Joblib files and are hash-checked before loading; never replace them with untrusted serialized models.

## Train and use your data

1. Rebuild the curated corpus with `python scripts/prepare_corpus.py`. This reads the downloaded CTU header capture, CTU detailed labels, c2db captures/README/lab keylog, and the two Sliver captures. It does not download or execute malware. Cached extraction is bound to source hashes, TShark version, extractor contract and filter.
2. Open **Model & evaluation → Train from curated labels**. Training uses the fixed corpus in `config/model.yaml`; upload alone never labels traffic or silently retrains the model. The real learned forest is saved under `var/models/`. The dashboard shows per-group held-out metrics, class counts, model version and global feature importance.
3. Open **Datasets** and upload PCAP/PCAPNG. TCP/UDP streams and visible DNS/QUIC metadata are extracted, mapped and analysed automatically by the dashboard. Only eligible TCP streams receive an ML score. Original capture and extracted flow hashes are verified before reanalysis. Packet, flow and time limits reject incomplete processing instead of accepting partial results.
4. CSV, TSV, Zeek ASCII and flat JSONL/NDJSON still support schema inspection and manual field confirmation. ML requires the exact registered packet feature contract; Argus fields cannot simply be renamed into compatible model features. Configure behaviour mappings for other tabular schemas.
5. Open **Findings**, filter exact source/destination IP, protocol or risk level, and review connections ordered by complete risk then ML score. Export evidence JSON for source hashes, stream/packet references, model inputs, threshold, rule measurements and configuration snapshots.
6. **ML score is uncalibrated.** Below-threshold does not mean benign. Full risk remains unavailable while required context/behaviour components are missing or risk fusion is disabled. Missing components are never converted to zero.

TShark stream IDs define the aggregation. First-observed packet direction determines sent/received measurements; only streams beginning with an initial SYN without ACK are eligible for ML. Original wire lengths include link headers and retransmissions. Duration is the observed timestamp span, not guaranteed connection lifetime. A SYN does not prove capture completeness. UDP/DNS/QUIC metadata is analysed by the evidence/rule layer, outside the TCP model. TLS/HTTP payload classification is not implemented.

## Configuration

Configuration is loaded per request; listening host/port and trusted-host middleware require restart. Findings retain the configuration and model version used at analysis time; changing the model invalidates analysis reuse.

| File | Responsibility |
| --- | --- |
| `config/app.yaml` | Storage, upload/row limits, formats, pagination and server |
| `config/integrations.yaml` | Access roles, bounded live capture, endpoint correlation and SIEM forwarding |
| `config/model.yaml` | Curated corpus, forest parameters, fixed threshold and capture limits |
| `config/dataset.yaml` | Null markers, label hints and explicit tabular mapping |
| `config/features.yaml` | Optional tabular feature registry; packet model features live in the versioned extractor/model contract |
| `config/detection.yaml` | Behaviour rules and aggregation |
| `config/risk.yaml` | Required components, weighted mean, levels and enablement |
| `config/providers.yaml` | Supplied exact-match context with attribution and observation time |
| `config/ai.yaml` | Optional local/hosted analyst, privacy, prompts, output limits and automatic triage |
| `.env` | Analyst endpoint/model/key and optional database/config overrides |

The exploratory periodicity rule is enabled: at least five connections grouped by source, destination, port and protocol, with interval coefficient of variation ≤0.15. The ACBackdoor sample has eight attributed connections with CV about 0.054. This rule is informed by that sample and is **not independently validated on it**. A triggered rule means regular communication, not malware attribution.

A configurable ratio-outlier detector also exists; it requires a saved confirmation identifying a real benign baseline. It is not enabled by default. Exact-match context, hosting-range matching, strict weighted risk fusion and configurable VirusTotal/AbuseIPDB/URLhaus/GreyNoise clients are implemented. There is no fabricated clean reputation result for a missing match.

## AI analyst: local or hosted models

The analyst reuses the OpenAI Python SDK as a client for compatible services. Using that SDK does not require a paid OpenAI endpoint. The default endpoint is local Ollama; AI remains disabled and no model is selected automatically.

Set `analyst.enabled: true` in `config/ai.yaml`, select a model through `ANALYST_MODEL`, and configure the endpoint/API below. Use the exact model ID your server or account exposes. Not every model supports structured output or every reasoning setting.

| Service | `base_url` | `api` | `response_format` | `api_key_env` | Completion token parameter |
| --- | --- | --- | --- | --- | --- |
| Local Ollama | `http://localhost:11434/v1` | `chat_completions` | `json_schema` | `null` | `max_tokens` |
| DeepSeek | `https://api.deepseek.com` | `chat_completions` | `json_object` | `ANALYST_API_KEY` | `max_tokens` |
| OpenAI | `https://api.openai.com/v1` | `responses` | `json_schema` | `ANALYST_API_KEY` | Responses uses `max_output_tokens` |

`ANALYST_BASE_URL` overrides the configured endpoint. Hosted credentials go in the environment variable named by `api_key_env`; the configuration API never returns their values. With `api_key_env: null`, the client uses a nonsecret local placeholder and does not reuse `OPENAI_API_KEY`. For another compatible server, configure its endpoint, model and supported format. Chat endpoints accepting only `max_completion_tokens` can select that `completion_token_parameter`. Optional `reasoning_effort` is passed only when configured; leave it `null` unless the selected API/model supports the requested value.

See the [Ollama compatibility documentation](https://docs.ollama.com/api/openai-compatibility), [DeepSeek JSON output guide](https://api-docs.deepseek.com/guides/json_mode), and [OpenAI optimization guide](https://developers.openai.com/api/docs/guides/model-optimization). Provider compatibility is tested with intercepted SDK requests; no live hosted model or local Ollama model has been evaluated here.

### Shared instructions and reviewed examples

`prompts/analyst_system.md` contains an explicit analysis rubric: check score completeness, interpret each measurement narrowly, weigh supplied context, separate supporting and counter-evidence, and cite the current case. Detector names are included with numeric measurements so a smaller model need not infer what was measured. Missing scores still require `needs_review`.

Optional `examples_file` points to a UTF-8 JSONL file of reviewed demonstrations. Each record has exactly `task`, `reviewed_by`, `evidence`, and `assessment`. Use a saved result's `evidence_supplied` as `evidence`, its corrected `assessment`, its task (`alert_summary`, `investigation` or `triage`), and the reviewer's name. The same Assessment schema and citation/action checks apply to examples. Files are byte-bounded; at most `max_examples` matching the current task are sent. No demonstrations or training outcomes are fabricated or bundled.

Review examples for both correctness and disclosure before enabling them: the selected examples, including their free-text interpretations, are sent to the configured model. They are approved reference material and are not automatically redacted by the current finding's privacy allowlists. Examples are instructions at inference time, **not trained weights**. Actual fine-tuning needs a particular base model, an appropriate training toolchain and reviewed training data; weights cannot be shared across unrelated architectures or arbitrary hosted APIs. These changes do not establish that a cheaper model matches a larger model's accuracy.

### Evidence and failure handling

- Current-case requests include engine evidence, detector identities and measured numeric metadata. Raw files, packet contents, arbitrary logs, original configuration and file names are excluded.
- Current-case IP/domain identifiers are excluded by default. Inclusion requires both the matching boolean flag and an explicit list of approved mapped fields. Optional numeric fields must also be allowlisted.
- Correlation is bounded to related findings in measured periodicity groups. It does not imply observed DNS/TLS activity or verified ownership.
- Manual investigation and configured automatic risk-level analysis share the same integration. Automatic analysis remains off by default and cannot trigger without a complete engine score.
- Both API paths enforce the Pydantic assessment schema and validate current-case evidence IDs, exact quotes and allowed actions. Refusals, truncation, empty content and malformed output fail without saving an assessment or modifying engine scores. There is no paid repair request or automatic fallback to another provider. The SDK's configured retries still apply to eligible transport/API failures.
- Cache identity includes the endpoint, API mode, model, reasoning settings, complete selected examples, prompts, schema and policy/privacy configuration. Changing these prevents reuse of an old assessment. Audit records retain supplied evidence, response ID, endpoint, model, prompt/example hash and token usage when the provider supplies it.
- Responses requests use `store=False`. Provider retention policies still need to be checked independently. Citation validity does not prove that the model's interpretation is correct. Results explicitly require human review.

### Compare cheaper models using reviewed cases

Create a held-out reference JSONL file using the example format plus a unique `case_id`. Each candidate model's predictions file contains `case_id` and the saved `assessment`; use `assessment: null` for a failed request. Missing predictions also count as failures. Run this offline check from the project directory:

```sh
python -m backend.app.analyst_evaluation reference.jsonl candidate.jsonl
```

The command makes no API calls. It reports valid-response counts, triage agreement, a confusion table, and supporting/counter-evidence selection precision and recall. Unknown/duplicate IDs and exact reuse of active prompt examples are rejected. Empty evaluation data produces an error, not a fabricated score. Keep related traffic from the same incident, host or capture out of both demonstration and held-out sets yourself; exact-content checks cannot detect every form of data leakage.

Run each candidate and a stronger baseline on the same held-out cases, with the same rubric and examples. Use human-reviewed answers as the reference, not an unchecked larger-model response. Review semantic correctness and missed high-priority cases separately; these metrics are not C2 detection accuracy. Saved token usage can support a cost comparison using the chosen provider's actual prices. No comparative accuracy or cost result exists until real cases have been assessed.

## Validation

```sh
python -m pytest -q -p no:cacheprovider
python -m ruff check --no-cache backend scripts tests run.py
node --check frontend/app.js
```

The suite includes real-capture extraction, strict unknown-label exclusion, incident/host split checks, model training and inference, periodicity evidence, ranked filtering, repeat-run reuse, tamper rejection and existing analyst/request integrity checks. It uses the supplied files and prepared corpus; it does not synthesize network traffic. See [MODEL_REPORT.md](MODEL_REPORT.md) for current verification and limits. Test success measures software behavior, not C2 detection effectiveness.
