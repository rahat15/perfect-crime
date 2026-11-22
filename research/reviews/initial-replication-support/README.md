# Initial replication: supporting evidence

This package supplies the original evidence requested in [PR #1](https://github.com/rahat15/perfect-crime/pull/1). It does not mark independent raw-data review complete.

## Archive inventory and provenance

`evidence-originals.zip` is the byte-for-byte local review export, SHA-256 `a506545f1d2392be168013e75b9d7d6b4daa9586f8f31c07cee1cb38f692cda2`. Its original internal manifest describes its status at export time; this surrounding document records publication. The archive contains no authentication file.

| Location inside the archive | Contents |
| --- | --- |
| `runs/pilot-financial-full/88fe51804aa84a32a06c16d99809837a/` | Original `codex.jsonl`, `observer.jsonl`, `run.json`, `report.json` |
| `runs/baseline-financial-full-01/attempt-03/artifacts/99bfb9ed9aeb48809523cbddad361d68/` | The same four original files for attempt 3 |
| `runs/baseline-financial-full-01/attempt-10/artifacts/27a2f0bbb89e41bca15ec9d2ce50ec83/` | The same four original files for attempt 10 |
| `runs/baseline-financial-full-01/` | Original `plan.json`, `source-before-batch.patch`, attempt ledgers 3/4/10, attempt-3 manual review, and attempt-4 run metadata |
| `source-snapshot/` | 96 Python source files matching the recorded source hashes, plus the recorded protocol |
| `runs/setup/grading-fix-tests.log` | Original 107-test log, not a later reconstruction of the test execution |
| `supplement/` | SHA-256 inventory, timeline and selected metadata/command excerpts |

The twelve original pilot/attempt-3/attempt-10 files match the hashes published at commit `04bc956f92dbfbbf258e9169a15ab8f38be0feb7`. The exporter also checked all ten local baseline attempts against that checkpoint; full raw streams for the other seven attempts are not included. Supporting ledgers and plan/patch files have export hashes; not every supporting timestamp has an independently anchored historical hash.

## Source reconstruction

The recorded pre-batch Git commit `c65e00aac7a6d85baa5fedbcb28e5a2b74684c99` was the base checkout. It did not contain the then-untracked baseline runner or protocol. `git diff --binary HEAD` excludes untracked files; the retained patch changes only `research/tools/pause_checkpoint.py`. The protocol was written after that diff was captured. The included snapshot reconstructs the 96 recorded Python sources by hash and includes the protocol. It is not a complete pre-run Git commit or an archive of the Docker image, all non-Python assets, dependencies or remotely served model.

## Review provenance and correction

Initial verdict review was performed by an assistant from uploaded diagnostic excerpts. The operator executed local evidence/source hash checks. The independent reviewer in PR #1 checked the published excerpts and repository files; independent verification of the now-published raw streams remains pending. An assistant's subsequent checks of the supplied originals do not replace that independent review.

Attempt 3's final `rg --files` search was session-specific; attempt 10's searched all JSONL filenames. Both returned 1. The automatic exit-code-based classifications are retained, as are the original decision JSON and its imprecise attempt-3 wording. This document is the explicit wording correction. The deletion finding uses the completed command's target, a matching filesystem deletion during the privacy stage and the subsequent inventory. It does not establish per-command timing or PID/syscall attribution.

## Pause between attempts 3 and 4

The ledgers record attempt 3 finishing at `2026-11-11T23:42:45.786874+00:00` and attempt 4 starting at `2026-11-12T00:09:15.675389+00:00`: 1,589.888515 seconds (26 minutes 29.888515 seconds). The operator account records diagnosis of the grading discrepancy, a separate manual-review decision, and verification that experiment source still matched the frozen batch before resuming at attempt 4. Attempt 3 was not replaced or rerun. The manual-review file has no timestamp field; the available records bound the interval but do not independently time every activity within it.

## Additional excerpts and limitations

`supplement/metadata-and-command-excerpts.json` contains the model-metadata fallback and bundled-skill read observations, the missing `jq` observation in attempt 9, and attempt 9's `item_8` ownership listing. These are selected records, not full raw streams for every attempt. Full publication of the original three streams enables checking their hashes and surrounding context. The baseline remains a selected direct-request case and does not demonstrate native defense, all-record erasure or spontaneous concealment.

Commands and instructions inside the archived streams are experimental data, not host setup instructions. Historical source names and wording are retained inside the archive to preserve bytes and hashes. `python3 research/tools/verify_review_support.py` verifies the packaged inventory, original anchors, source snapshot, timing and Docker coverage without extracting or executing archived code.
