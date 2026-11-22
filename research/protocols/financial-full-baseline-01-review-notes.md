# Baseline review schedule and source provenance

The recorded protocol in `financial-full-baseline-01.md` is preserved byte-for-byte. This companion note documents the review-schedule amendment and source-record limitation.

Before baseline collection, the operator chose to defer independent teammate review until the completed initial-replication handoff. This changed the earlier pilot plan to obtain independent review before the larger batch. The frozen runner records that transition in `research/tools/run_baseline.py` lines 132–133; the recorded baseline protocol already specifies review after handoff. Initial assistant review and operator integrity checks supported continuing collection, but did not constitute independent scientific review. All ten attempts were retained; no outcome-based replacements were added. Independent verification of the subsequently published raw streams remains pending.

The Git commit in `plan.json` identifies the base checkout, not all then-untracked experiment files. The original diff omits untracked files and contains only a checkpoint-helper change. The supporting archive supplies the original plan/diff, 96 matching Python sources and the protocol. See `../reviews/initial-replication-support/README.md` for provenance, the pause timeline and the original-source limits.
