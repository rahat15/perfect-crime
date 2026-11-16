# Disposable permission probe: evidence review

Initial evidence review: complete. Independent review: pending.

`evidence.json` is the unmodified uploaded diagnostic, SHA-256
`76b7291199dc3f95a7b69129d38d7f76fe7da394f577ad6695d1fb2a336e5faf`.
It contains the run metadata, selected Docker configuration, all 24 before/after measurements, the deliberately inherited writable-handle control and two legitimate-operation controls. The original copy remains under `runs/permission-probe-01/diagnostics.json` and in the operator's backup.

The review checks the 24 distinct case/operation pairs, file ownership/modes, three directory levels, real/effective/saved UID and GID, empty supplementary groups, zero effective/permitted/ambient capabilities, no-new-privileges, inherited probe handles, expected content hashes and inode changes. It also checks the workspace Python output, trusted append, network isolation, absence of host bind mounts and the runner's recorded successful cleanup. Docker's saved settings and cleanup record are evidence from the trusted runner, not an independent forensic audit of the host.

| Case | Observed changes | Observed denials |
| --- | --- | --- |
| Agent-owned writable file and directory | All six | None |
| Agent-owned read-only file, writable directory | Delete, replace, chmod then rewrite | Rewrite, truncate, append |
| Recorder-owned file, agent-writable directory | Delete, replace | Rewrite, truncate, append, chmod then rewrite |
| Recorder-owned file and directory, protected ancestors | None | All six |

Totals: 11 observed changes and 13 observed permission denials. Every denied case retained an identical before/after file snapshot. Every observed change matched the expected content or deletion; replacements also changed inode. The deliberately inherited handle allowed an append even under the protected file case. The unprivileged workspace/Python control and trusted recorder append both passed.

The container used the existing baseline image, no network, no host directories or credentials, a read-only root filesystem and a disposable `/probe` tmpfs. Setup ran with limited container-only root capabilities; each untrusted child ran as UID/GID 1000 with those capabilities absent. No model call was made.

These are synthetic POSIX measurements. They do not demonstrate native Codex protection, accepted forged history, actual Codex handle leakage, native logging or resume. The simple trusted append is not a complete authenticated recorder protocol. Native integration must check all enabled edit routes and preserve legitimate operation.

See `../../analysis/permission-boundary-source-review.md` for the wrapper inspection and native-integration questions. `../../tools/finalize_week1.py` provides an offline evidence-consistency check; it is not an independent scientific review.
