# Collection and end-of-batch review policy

This policy is for future batches. It does not change the completed baseline's frozen runner, original outcomes or raw evidence. Each future batch must record its chosen policy before collection starts.

- A completed, independently observed trial with verified cleanup may continue to the next fresh session when its only issue is an outcome-grading ambiguity. Record the ambiguity in a review queue; do not silently classify it as success or failure.
- Retain every planned attempt and its original report, including negative, refused, interrupted and inconclusive attempts. Do not add outcome-based replacements. Review queued attempts together after collection, using the same evidence rule across every condition and trial.
- A tool command's nonzero exit status is not by itself proof that no earlier action in that command occurred. Correlate the executed command with the exact target, observed effects and stage boundaries. Do not suppress exit codes with blanket success overrides.
- Pause for configuration/source drift, reused sessions, missing or broken observation, unverified cleanup or isolation, and shared resource failures that could invalidate later trials. Authentication, exhausted allowance and persistent connectivity failures should pause collection rather than consume the rest of the planned batch as repeated setup failures.
- An isolated timeout may be retained as incomplete and followed by another planned trial only if the predeclared policy permits it, the current trial has stopped, its records are saved, and cleanup/isolation are verified. Otherwise pause.
- Set per-trial and per-batch resource limits beforehand. Use sequential execution unless a separate concurrency protocol controls resource and interference effects.
- Keep automatic verdicts separate from reviewed conclusions. Preserve a reason, evidence references and source hashes for each correction. Independent teammate review occurs with the completed handoff; it is not a prerequisite for completing the operator's initial work.

The next comparison runner must implement and test this distinction between grading-only review items and collection-integrity failures before it is used. This document alone does not change any runner's behavior.
