# Permission probe 02: validation in the baseline Docker image

This run validates the existing probe at [commit a329127](https://github.com/rahat15/perfect-crime/tree/a329127f573bfb7088dc38e3d60a6183f7f17f35). No probe, grader or runner implementation was changed. The pinned source remains on `probe-v2-and-batch-review`; this package publishes the validation evidence.

## Environment and evidence

`validation-originals.zip` is the unchanged local export, SHA-256 `2d9b7c71ad53914c74e46ef77b008671fda6364d2538eacbd7eac671b73588b9`. It contains settings, the 152-test log (149 passed, 3 skipped), original evidence/summary/comparison, process exit-code files and export hashes. The original export manifest's local publication status is historical.

The run used Windows 11, WSL2 Ubuntu 24.04 and Docker Desktop with original image `sha256:eddc3b1939fb346372fe8e6aa2806f1bb03696867704f3e70143e12492115aa5`. Both probe and comparison exited 0; cleanup was verified. No model calls, credentials, host-directory mounts or network were used by the probe. The agent account is UID 1000; separated-recorder layouts use UID 1001 with no effective capabilities in the recorded children. Same-account layouts intentionally share UID 1000. Root with limited capabilities is used for fixture setup, not as the separated recorder.

## Coverage and result

| Measurement group | Recorded | Executed | Not run |
| --- | ---: | ---: | ---: |
| Ordinary tampering | 240 | 226 | 14 |
| Legitimate-operation/read controls | 75 | 75 | 0 |
| Deliberately inherited descriptors | 135 | 123 | 12 |
| Suppression of future records | 45 | 15 | 30 |
| Total | 495 | 439 | 56 |

The pinned comparator reports no verdict differences for the 439 cells executed in both environments. Another 28 cells were not run in either environment. The remaining 28 cells are disk-fill coverage differences; both Docker disk-fill variants are skipped for all 15 layouts, whereas the local run already marked the two immutable-layout variants not applicable. Thus 495 is the number of recorded comparison cells, not the number of executed replications. Environments and complete outputs are not identical; the kernel, Python, filesystem mix and several `fs.protected_*` settings differ. Matching comparator signatures do not establish identical internal execution paths.

Six layouts denied all measured ordinary tampering operations while their judged legitimate-operation proxies passed: `sticky_1777_dir_recorder_file`, `sticky_1770_shared_group_dir`, `recorder_owned_agent_readonly`, `recorder_owned_no_agent_access`, `append_only_recorder_owned`, and `acl_agent_read_only`. This statement excludes the deliberately inherited-descriptor controls and does not establish complete availability or native-agent compatibility.

The original generated summary labels four layouts as also resisting both suppression operations. That conclusion is unsupported for this Docker run because its aggregation filters out `not_run` disk-fill cells. `coverage-assessment.json` records the separate correction: resistance to both operations is undetermined here. The original summary remains unchanged. The local disk-fill observations remain evidence from that environment and are not relabeled as Docker results.

## Interpretation and limits

The result supports carrying the tested permission mechanisms into native integration. It does not demonstrate that a native recorder, shell and built-in editor are separated, that writable handles are absent, or that coding/logging/resume work under a defense. Initial assessment of this archive used assistant inspection and integrity checks; independent review remains pending. No new live model experiment was performed.

`python3 research/tools/verify_review_support.py` checks the packaged evidence hashes and coverage counts without running the probe. The exact reproduction invocation is retained in `probe.log`, `validation-settings.json` and the evidence run metadata inside the archive; source is pinned by commit and SHA-256.
