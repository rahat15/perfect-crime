# Process observation calibration and sandbox startup controls

This protocol precedes native recorder/tool measurements. It makes no model requests and uses the existing pinned baseline image. Original baseline experiments and the first environment inventory are retained.

Runtime sources and this protocol are committed before collection. The runner checks their bytes against that commit and retains a source snapshot and SHA-256 inventory with the observations. Calibration results are separate from the completed replication evidence.

## Observer calibration

A separate observer container shares only the disposable target's PID namespace. It has container-local `SYS_PTRACE` and `DAC_READ_SEARCH` capabilities for `/proc` inspection. Target processes run as UID/GID 1000 with no added capabilities and no-new-privileges. No host directories, credentials, Docker socket or host PID namespace are mounted or shared. Network access is disabled.

The observer samples process identity, real/effective/saved/filesystem IDs, capabilities, executable paths and file-descriptor metadata (access flags, target path, and available inode/mount/position fields). It does not collect command-line arguments, environment contents or process memory. PID plus process start ticks distinguish process identities. Samples are bounded by time, process count and descriptor count; access errors and truncation remain explicit.

Three synthetic controls hold processes open for three seconds: a writer whose child inherits no target handle, a child that independently opens the target read-only, and a deliberately inherited append-capable handle. A passing calibration requires all three distinct cases, at least three complete matching parent and child samples per control, a matching parent relationship, expected final fixture bytes, measured unprivileged target credentials, a trusted observer identity, matching PID namespaces and a clean observer finish with the recorded sample count intact.

These controls calibrate the instrument; they are not native logging or resume experiments. Polling can miss short-lived activity. Descriptor snapshots are not atomic across a process, and a writable handle shows access rather than proof of an actual write. Native history integrity requires independent content/operation evidence as well.

## Sandbox compatibility comparison

Two fresh containers use identical image, user, capabilities, no-new-privileges, network isolation, writable temporary directories and resource limits. One uses Docker's default seccomp filter; the other disables that filter only for its own lifetime. This diagnostic does not change daemon settings, the completed baseline or the selected defense.

Each container records the CLI version, a direct Python marker control, an unprivileged user-namespace startup control and `codex sandbox` launching a harmless Python marker. The command is passed directly after `codex sandbox`; there is no `linux` subcommand in the inspected build. The first inventory's `codex sandbox linux --help` invocation therefore did not provide Linux-subcommand help; its namespace error is retained as a startup observation, not a root-cause diagnosis. The corrected inventory helper omits that invocation. Nonzero probe exit codes and timeouts are retained, and independent probes continue. Controller/isolation/cleanup failures terminate the collection and retain its partial evidence.

A difference can support an environment-specific role for the changed filter. Failure in both conditions does not isolate a cause. Successful sandbox startup alone does not demonstrate history protection or native edit/resume compatibility. A later comparison must hold outer container policy constant across its baseline and defense conditions.

## References

- Docker seccomp documentation: https://docs.docker.com/engine/security/seccomp/
- Linux `/proc/pid/fd` access and descriptor semantics: https://man7.org/linux/man-pages/man5/proc_pid_fd.5.html
- Installed CLI usage: unchanged original inventory copied to `runs/native/environment-inventory-01/environment.json`; SHA-256 `a4def104fca04a2b29f6420323cc806e6d6b0e4cbada49f4106a8812ad3ae43e`.
