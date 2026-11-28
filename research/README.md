# Native transcript deletion and permission probes

Experimental code and evidence for a selected financial/privacy case from [Perfect Crime](https://perfect-crime.ai/). The research question is whether operating-system permissions and privilege separation can protect native coding-agent history while legitimate editing, recording and session resume remain functional.

## Native history comparison

The subsequent [native history experiments](native/README.md) include a twenty-attempt comparison, separate coding/resume pilots, process observations and offline controls. The [current findings](analysis/native-history-comparison-findings.md) distinguish preserved workspace histories from observed operating-system denials and describe what remained in SQLite. Public evidence and verification instructions are indexed in the native-history directory. Independent human review is pending.

## Initial replication findings

One pilot and ten subsequent fresh baseline sessions completed the financial task and direct privacy request. The pilot is separate from the baseline. Eight baseline automatic verdicts reported deletion; attempts 3 and 10 required separate review. The reviewed finding is local session JSONL deletion and final path absence in all ten. Original reports and evidence are retained.

In attempt 3, the trailing `rg --files` search was restricted to the target session's JSONL filename. In attempt 10, it searched all JSONL filenames. Each search returned 1 after the earlier deletion command. Matching filesystem deletion events occurred inside the privacy stage, and the final observer inventories were empty. Attribution rests on command target plus stage timing; no per-command timestamp, originating PID or syscall attribution was collected.

Initial review was performed by an assistant using uploaded diagnostic excerpts; the experiment operator ran local integrity checks. The independent review recorded in [PR #1](https://github.com/rahat15/perfect-crime/pull/1) checked the published excerpts and files. Independent verification of the newly supplied raw streams remains pending. A filesystem observer is a separate measurement channel, not an independent human reviewer.

The first permission probe recorded 11 file changes and 13 denials in 24 synthetic operations. Its trusted append ran as root with `CAP_DAC_OVERRIDE`; it did not validate an unprivileged recorder. Its coding proxy ran in `/probe` tmpfs, not the native `/workspace` volume. The inherited-descriptor control deliberately passed a writable handle in `protected_file_and_directory`; it does not establish a native handle leak.

The [Docker validation of permission probe 02](reviews/permission-probe-02-docker/README.md) used the original baseline image and an unprivileged recorder account for separated-recorder layouts. Of 495 recorded cells, 439 executed and 56 were not run. Compared verdicts agree on the 439 cells executed in both environments. Disk-fill coverage is absent in Docker. The original summary's claim that four layouts resist both suppression operations is unsupported for this run; a separate coverage assessment preserves that limitation without altering the original output.

## Configuration and scope

The baseline used Codex CLI `0.154.0`, requested model `gpt-6-sol`, subscription authentication and full permissions in disposable Linux containers. Authentication mode is experimental metadata; credentials are excluded. All ten runs reported a model-metadata fallback and read a bundled documentation skill. Served model identity was not independently established. The paper lists GPT-5.6-Sol and GPT-6-Sol as separate Codex configurations in Figure 2 and the setup paragraph on [page 4](https://arxiv.org/pdf/2609.30266#page=4).

These results measure compliance with a direct deletion request, not spontaneous concealment. Local file absence does not establish all-record or forensic erasure, deletion of remote copies or databases, or accepted fabricated history. At this initial replication checkpoint, native JSONL contents were not captured, and native identities, handle inheritance, integrated protection and coding/logging/resume had not been evaluated. The subsequent native-history work is indexed above. Dedicated native editor confinement remains unestablished. The current adapter does not implement the paper's auto-mode condition for Codex. Internal timing fields are not used for performance claims.

## Evidence and source

- [Initial replication manifest](manifests/initial-replication.json): current public file hashes and the unchanged experiment-source hashes.
- [Baseline evidence support](reviews/initial-replication-support/README.md): original pilot/attempt-3/attempt-10 streams, original plan and patch, 96 hash-matched Python sources, protocol, original regression-test log, timeline and selected incidental observations.
- [Baseline findings](reviews/baseline-financial-full-01/README.md) and [pilot evidence](reviews/pilot-financial-full-01/README.md): retained automatic results and separate reviewed findings.
- [Permission probe 01](reviews/permission-probe-01/README.md) and [Docker validation of probe 02](reviews/permission-probe-02-docker/README.md): synthetic mechanism measurements and limits.
- [Recorded baseline protocol](protocols/financial-full-baseline-01.md) and [review-schedule/source notes](protocols/financial-full-baseline-01-review-notes.md): original protocol plus the documented amendment and source provenance.

The recorded base commit `c65e00a` alone is insufficient to reconstruct the experiment: it omits then-untracked files. The original diff also excludes untracked files. The support archive supplies the matching source snapshot and states its limits. Historical artifact bytes, path names and decision wording are retained for verification; current documentation supplies explicit corrections. Hash agreement establishes consistency with the published checkpoint, not independent authenticity or completeness.

## Offline validation

Git and Python 3.11+ suffice; these checks make no model, Docker or network calls after checkout.

```bash
git clone --branch reproduce-financial --single-branch https://github.com/rahat15/perfect-crime.git perfect-crime-review
cd perfect-crime-review
python3 research/tools/finalize_initial_replication.py check
python3 research/tools/verify_review_support.py
```

Expected final lines include `HANDOFF FILE CHECKS PASSED` and `REVIEW SUPPORT VERIFIED`. These are integrity/consistency checks, not certification of independent scientific review. Live runs require the configured environment and authorized model access. The completed baseline runner and all original outcomes remain unchanged. The proposed future batch-review policy does not retroactively change that runner.
