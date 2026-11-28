# Real-Docker preflight after the launcher hash correction

The corrected Step 5 preflight passed with exit code 0 on Docker Server 29.9.3 under Ubuntu 24.04 in WSL. The operator ran the preflight from a Git archive of `f59bd18be555cea0ddfbd84610719a6eba1b6fd5` using the two existing images.

| Check | Result |
| --- | --- |
| Baseline and derived images | Both present |
| Native executable SHA-256 | Matched its pin in both images |
| JavaScript launcher SHA-256 | Matched its own pin in both images |
| Derived shell wrapper | Original shell present and its digest differs from the wrapper |
| Preflight | Passed, exit 0 |

The previous preflight at `163182f6` used the native executable's pin for the launcher. The earlier failure remains in the sibling directory [account-separation-preflight-AmZXYp](../account-separation-preflight-AmZXYp/). The launcher digests and both image IDs are identical across the two reports.

## Step 6 at this checkpoint

The preflight exits before session collection. The run reported here contributed zero of the six planned real-Docker sessions. The planned counts are two full-access, two workspace, and two account-separation sessions. There is no Step 6 outcome to report at this checkpoint. The earlier four marker sessions and stand-in runs are separate.

For a later results commit, retain the full original output directory, including partial or failed slots. Report collected and interpretable counts out of two for each condition, the observed history outcome, and whether resume restored the expected input. Record the reason if collection stopped early.

## Evidence

`preflight.json` contains the report, paths, full digests, and image IDs. `preflight.stderr.txt` contains standard error. `exit-code.txt` records the exit code displayed in the terminal.
