# Account-separation blocker review

Study revision: 163182f6. The parent folder contains the original step 5 output.

Step 4 passed on real Docker. The recorder ran as UID 1000 and the wrapped
shell as UID 1002, with all five shell capability sets zero.

Step 5 exited 1. Both images were present and the shell-wrapper check passed.
The preflight hashed the baseline and derived JavaScript launchers. Both
matched the archived launcher SHA-256 (61b0194f...), but the code compared
them with the native executable pin (3188814c...). Independent checks of
the native executable in both images matched that pin.

The simulated Docker helper returns the expected pin for both launcher paths
without reading their contents. This explains why its preflight test can pass
while the real preflight fails.

Ordinary-user offline suite: 89 passed, 30 skipped, 0 failed in 34.09 seconds.
Exit code 0. All 30 skipped tests require root. No follow-up sessions ran.
