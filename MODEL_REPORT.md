# TCP model implementation and confidence report

This records the original model experiment. The later feature-completion status and current verification are in [FEATURES.md](FEATURES.md). Missing integration/protocol features listed below describe the earlier snapshot and have since been implemented as documented there.

The application now extracts TCP flows, applies evidence-backed labels, trains a real local Random Forest, records measured evaluations and scores uploaded captures. **The trained model is not reliable enough for C2 detection: it missed every source-attributed C2 flow in the external evaluation.** No high-accuracy claim or interchangeable LLM weights are being made.

## What was built

| Result | Evidence | Implementation confidence (0–100) |
| --- | --- | ---: |
| Consistent packet extraction | TShark TCP streams, wire-byte features, source hashes, packet/flow/time limits, rejection of failed/partial processing | 92 |
| Reproducible labelling | `scripts/prepare_corpus.py`, `../../datasets/training/label-audit.csv`, exact label basis and capture hash for each selected stream | 90 |
| Local model and evaluation | Learned forest under `var/models/`, fixed threshold, separate held-out groups, model/corpus/version audit | 94 |
| Scoring and behavioural evidence | Model inputs/scores, periodicity, immutable evidence, model-aware run reuse; missing risk components preserved | 90 |
| Dashboard integration | Automatic PCAP analysis, model training/results, ranking, source/destination/protocol/severity filters, pagination and evidence export | 94 |
| Validation and run instructions | Real-file integrity suite, Chromium workflow checks, pinned dependencies, README | 94 |
| Generalization to unseen C2 | Baseline and exploratory transfer tests fail; more code does not resolve the current data limitation | 10 |

These are engineering judgments about the stated results, not statistically calibrated probabilities or measured model confidence.

## Labels and split

The preparation script reconciles label meaning with packet extraction, rather than mixing Argus aggregate features with TShark features. CTU labels are matched by directed IPv4/TCP tuple, start time within 5 milliseconds and duration within 20 milliseconds. CTU times are interpreted in `Europe/Prague` (CEST on this date). Only unique matches with an initial SYN are selected.

| Source | Label evidence | Training | Evaluation |
| --- | --- | ---: | ---: |
| CTU-13 scenario 5 | Explicit `From-Botnet-...-TCP-CC...` labels | 24 C2 | — |
| CTU normal clients .134 and .170 | Matching `From-Normal` labels | 1,117 normal | — |
| CTU normal client .164 | Matching `From-Normal` labels | — | 539 normal |
| c2db ACBackdoor | Eight TCP streams with matching POST host/path, using the supplied lab TLS keylog | — | 8 C2 |
| c2db Backstage | One stream with matching visible POST host/path | — | 1 C2 |
| Sliver 2021-10-20 | Publisher-attributed `23.152.0.91:443` within this capture | — | 91 C2 |
| Sliver 2022-08-30 | Publisher-attributed `65.20.115.15:8557` within the filtered capture | — | 1 C2 |

Of 3,256 extracted TCP streams from the selected sources/CTU host filter, **1,781 are included and 1,475 excluded**. Background, unsupported, unmatched and non-C2 botnet traffic are not assigned benign labels. The audit retains exclusions. Source attribution is weaker than independent per-flow ground truth; a matching stream may include ancillary exchanges alongside C2.

The normal holdout is host-disjoint but shares the CTU capture with training. External C2 captures are incident-disjoint and positive-only. There is no independent modern benign capture, so no deployment precision, prevalence or overall accuracy is established. The 91 Sliver connections are related observations from one incident, not 91 independent malware experiments.

Original publisher metadata remains in its source manifest as an initial inspection record. The current derived labels and split are in `../../datasets/training/manifest.json`; hashes connect all artifacts to their source data.

## Features and measured performance

The seven predictors are duration, total packets, source bytes, destination bytes, mean wire bytes per packet, source packet fraction and source byte fraction. They exclude addresses, ports, capture identity, absolute dates, source labels and known indicators. Lengths include link headers and retransmissions; no payload decryption is used to compute model features. Initial SYN and extractor contract control eligibility, not classification.

The forest has 200 trees, maximum depth 8, minimum leaf size 2, balanced class weights and seed 42. Threshold 0.5 was fixed before evaluation and was not adjusted to improve the reported results. `predict_proba` output is displayed as an **uncalibrated ML score**; `ml_probability` remains null.

| Baseline test | Detected / attributed C2 | Normal false positives |
| --- | ---: | ---: |
| Sliver 2021 | 0 / 91 | Not measurable |
| Sliver 2022 | 0 / 1 | Not measurable |
| ACBackdoor | 0 / 8 | Not measurable |
| Backstage | 0 / 1 | Not measurable |
| CTU normal holdout | Not measurable | 5 / 539 = 0.93% |

Machine-readable baseline record: `../../datasets/training/evaluation.json`. The active artifact uses 1,141 training streams, including only 24 C2 examples from one historical Virut incident. It is retained as a reproducible research baseline, not promoted as a successful detector.

A second, exploratory test (`scripts/evaluate_transfer.py`, `transfer-evaluation.json`) trains across the available labelled families while leaving each positive group out in turn. Each fold also excludes the same normal test host. **It detects 0/125 held-out positive streams across the five groups**; each fold flags 2–6 of the same 539 normal streams. These repeated normal tests are not independent samples. This follow-up was designed after viewing the baseline failure, so it is not an untouched final test. No threshold tuning or replacement of the active model follows it.

The ACBackdoor-informed periodicity rule detects its eight regular connections, but that is a sample-informed heuristic demonstration, not independent validation. It does not repair the failed classifier benchmark.

## Verification

- 31 automated tests pass; one optional supplied-tabular-file test is skipped. The new tests use actual c2db captures and the curated corpus.
- Ruff and JavaScript syntax checks pass.
- Chromium checks pass for model training, all four PCAP uploads, automatic analysis, 100/4-row pagination, destination filtering to eight flows, detail review and evidence download. No application JavaScript errors were observed.
- Mobile evidence view was checked at 390px with no document overflow; desktop model/findings/evidence screenshots are retained under `/tmp/hellopanda-*.png`.
- The local workspace contains four imported captures and 104 scored TCP streams. Every score remains separate from a final risk verdict.
- TestClient and browser/server checks required sandbox exceptions for thread/socket access. Starlette emits an upstream AnyIO alias deprecation warning. Windows/macOS extraction and production deployment were not tested.

## Remaining work against the brief

Working: tabular inspection/mapping, TCP capture extraction, local forest training and persisted weights, measured evaluation, periodicity, configurable ratio-outlier implementation, supplied context matching, strict configurable fusion, evidence provenance, optional provider-configurable analyst, SOC-style review/filter/export workflow.

Still incomplete: a validated detector with useful unseen-C2 recall; UDP/DNS/QUIC feature extraction; validated rare-destination and similar-flow rules; live threat-intelligence and shared-infrastructure attribution; production authentication/queues/sensors/SIEM/EDR integrations. Risk fusion and automatic LLM triage remain disabled because the current model/context do not support a trustworthy complete risk assessment. Screenshots in c2db were not converted into fabricated packet data. The presentation brief in `message.txt` has not been turned into slides in this implementation task.

No live Ollama, DeepSeek or OpenAI analyst quality/cost comparison was run. The existing rubric, optional reviewed examples and strict citation/schema checks can support smaller models, but do not prove parity with stronger models. The learned Random Forest is the model-independent local detection layer; its weights are not neural LLM fine-tuning weights.

The most useful next data is varied **modern normal TCP traffic and multiple independent incidents per C2 family**, with provenance and collection details. Preserve fresh incidents for final testing; now-observed benchmark captures should not become a hidden source of tuning. More near-identical beacons from one incident do not establish broader coverage.

Sources: CTU-13 / Garcia, Sebastian, Malware Capture Facility Project (retained source README); c2db supplied README/PCAPs; Malware-Traffic-Analysis.net incident pages and IOC file. The Immersive Labs Sliver guide informs future DNS/HTTP observables, but the supplied TLS captures do not establish DNS or WireGuard detection.
