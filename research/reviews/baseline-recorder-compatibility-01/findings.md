# Recorder functionality in the baseline image

In one offline Docker container, a recorder running as UID 1001 and a workspace user running as UID 1000 operated on separate temporary filesystems. The recorder created a synthetic record, appended to that same file, read back the continuation, and created and read the next record in both layouts. The workspace user created and read its own file in both layouts. It could read the recorder's file in the read-only layout. The read returned permission error 13 in the private layout.

These are four role-by-layout observations from one container. They agree with the recorder and read outcomes in the corresponding stored Probe 02 and Probe 03 cases. The earlier workspace control included an edit and test. The current workspace control covers file creation and readback. The run measured ordinary Linux file operations. The separate four-session native study measured model recall.

| Existing measurement | Recorded | Executed | Skipped |
| --- | ---: | ---: | ---: |
| Probe 02, sandbox | 495 | 467 | 28 |
| Probe 02, original baseline image run | 495 | 439 | 56 |
| Probe 02, local pre-mounted filesystems | 495 | 467 | 28 |
| Probe 03, sandbox | 273 | 261 | 12 |

The earlier sandbox and baseline-image Probe 02 runs agree on the verdicts for all 439 cells that both executed. Another 28 were measured only in the sandbox, and both environments skipped 28. The pre-mounted run is a separate execution in a local environment. The full Probe 03 suite has a sandbox measurement. Both the additional Probe 02 capacity coverage and full Probe 03 baseline-image validation remain open. The single-container recorder check contributes no cells to these earlier denominators.

The accompanying coverage.json contains the original report digest, the projected observations, and references to the source records. Baseline-image report SHA-256: `ee476097cf9187a014ed9c014ecff2c5c7b4365450f0070e0a18c14cbf21a6dd`.
