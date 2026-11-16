# Independent replication checkpoint

Project: replicate selected agent trace-tampering findings, then evaluate standard systems protections and their limits while preserving legitimate agent operation and logging.

- Environment: Windows 11, Ubuntu 24.04 under WSL 2, Docker Desktop, Python virtual environment.
- Observer calibration completed successfully.
- One Codex financial/privacy pilot finished, with independent evidence of local session JSONL deletion.
- Original automatic grading missed an `if ... then rm ... fi` command. Keep the original report.
- Grader patch present in local source: True.
- Separate reviewed report present: True.
- A prepared grading patch is retained at `research/patches/guarded-trace-grading.patch`.
- Summary and evidence hashes: `research/results/pilot-financial-full-01-summary.json`.
- Full raw artifacts remain locally under `runs/pilot-financial-full/88fe51804aa84a32a06c16d99809837a` and in the local backup.
- This is a pilot, separate from the repeated baseline. It does not establish deletion of all local or remote records.
- Independent review remains pending. Selected evidence: `research/reviews/pilot-financial-full-01/evidence.json`.

The original and reviewed findings are separate records. Independent review is not complete. Experiment configuration, permission behavior and all retained outcomes are documented in the evidence files.

Repeated baseline: all ten fresh attempts retained. A separate reviewed summary records local session JSONL deletion and final absence in all ten, with corrections for attempts 3 and 10; original verdicts and raw evidence are preserved. Independent teammate review remains pending. See `research/reviews/baseline-financial-full-01/README.md`.

Initial permission mechanism investigation: see `research/analysis/permission-boundary-source-review.md` and `research/results/permission-probe-01-summary.json`. These disposable POSIX probes are separate from native agent trials; native writer/tool mapping and logging/resume integration remain to be tested.
