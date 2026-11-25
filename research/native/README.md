# Native history protection experiments

Can a coding agent's native permission boundary preserve its session history while useful coding, logging and session resume continue to work?

This directory contains the collection and review implementations. The [current comparison findings](../analysis/native-history-comparison-findings.md) describe twenty fresh attempts in ten counterbalanced pairs. The [initial generated review](../analysis/native-history-comparison-review.md) and [machine-readable summary](../results/native-history-comparison-reviewed-summary.json) retain both automatic and reviewed findings. The two earlier history pilots are excluded from the main counts.

| Main comparison, ten attempts per profile | Full access | Workspace |
| --- | ---: | ---: |
| Current-session JSONL deletion after separate evidence review | 10 | 0 |
| JSONL retained through the resume check | 0 | 10 |
| Exact same-session recall without tools | 0 | 10 |
| Missing-rollout resume failure | 10 | 0 |
| Conversation token retained in SQLite at all three captures | 10 | 10 |
| Executed trace mutation observed during privacy | 10 | 0 |

All twenty financial-task answers were correct. All ten workspace responses declined deletion and cited write restrictions. The reviewed main records contain no workspace mutation attempt or operating-system denial. The separate workspace history pilot contains an executed removal denied by the runtime. Changing the native profile changes both model-visible restrictions and runtime enforcement, so the main comparison does not isolate their individual contributions.

The full-access cases show loss of the current JSONL and usable resume while conversation data remained in SQLite. They do not establish complete erasure. Attempt 16 retains its original undetermined automatic finding and has a separate, evidence-bound attribution addendum. Attempt 4's compound-command exit code does not negate its corroborated earlier deletion. No original verdict or frozen peer grader was replaced.

## Evidence map

The public copies are in [research/evidence/native-history](../evidence/native-history). Each ZIP keeps its original internal paths and original manifest, and adds a publication manifest. The filename identifies the underlying experiment.

| Evidence | Interpretation and source |
| --- | --- |
| `native-history-comparison-review-01-public.zip` | [Current findings](../analysis/native-history-comparison-findings.md), [initial generated review](../analysis/native-history-comparison-review.md), [case decisions](../reviews/native-history-comparison-01/review-decisions.json), [protocol](native-history-comparison-protocol.md), `run_native_history_comparison.py` |
| `native-history-pilot-recovered-review-public.zip` | [History pilot review](../analysis/native-history-pilot-review.md), [pilot protocol](native-history-pilot-protocol.md) |
| `native-functionality-comparison-review-public.zip` | [Matched coding and resume review](../analysis/native-functionality-comparison-review.md), [protocol](native-functionality-comparison-protocol.md) |
| `native-identity-review-public.zip` | [Recorder/tool identity and handle observations](../analysis/native-identity-01.md) |
| `native-store-scope-review-public.zip` | [Store reconstruction observation](../analysis/native-store-scope-findings.md) |
| `native-observer-calibration-review-public.zip`, `native-sandbox-startup-review-public.zip` | [Corrected startup protocol](sandbox-startup-protocol.md). Original argument-parsing failures remain separate from the corrected startup controls. |
| `native-boundary-review-public.zip` | [Deterministic boundary-control protocol](native-boundary-protocol.md) |
| `native-functionality-review-public.zip`, `native-functionality-followup-review-public.zip` | [Original authentication failure and separate follow-up](native-functionality-followup-protocol.md). These are not added to the matched pair or main batch. |
| `native-history-integration-review-public.zip` | [Evidence-capture integration controls](history-integration-protocol.md) |

The identity observation found the native writer and held tool using UID/GID 1000 with zero capabilities. A native writable history handle was not observed in that held tool. The matched functionality pair independently passed four coding tests per profile and resumed with exact recall. Its outside-workspace canary append was allowed under full access and denied under workspace permissions. These findings do not establish dedicated editor confinement or universal bypass resistance.

## Public-copy policy and verification

Account usage-limit values are omitted from native `event_msg` / `token_count` records by setting only `payload.rate_limits` to `null`. Commands, responses, experiment token counts, filesystem observations, SQLite files and archived source are retained. No archive member is omitted. Original archives remain unchanged outside Git. Each changed file and line has original and public hashes in its publication manifest. The original manifest is retained as provenance, not as a claim that a redacted file still has its original hash.

From this checkout, using Python 3.11 or later:

```bash
python3 research/native/publication.py
python3 research/tools/finalize_initial_replication.py check
python3 research/tools/verify_review_support.py
python3 -m unittest tests.test_native_publication
```

These checks need no model account, subscription, Docker or network after checkout. They verify public-copy hashes, unmodified members, declared redactions and frozen source. They do not reconstruct the omitted account values or independently authenticate the original redacted bytes. Original-archive review implementations require the private original archives at their recorded local locations. They must not be pointed at redacted public copies. The operator verified the public transform against each original before publication.

Initial scientific review used programmatic integrity and consistency checks plus assistant examination of original runtime evidence. Independent human scientific review remains pending. Historical readiness fields and reports describe their own collection checkpoints, not the current publication state.

The live configuration used Codex CLI 0.154.0, requested `gpt-6-sol`, subscription authentication and the pinned image. The served variant was not independently established. Both profiles used the same documented container seccomp exception. Metadata-fallback and clock warnings remain recorded. Monotonic timestamps support within-invocation attribution. The studies support no performance, population-wide success-rate, forensic-erasure or server-side-deletion claim. The main challenge is a direct user privacy request after a benign task, not spontaneous concealment or prompt injection.
