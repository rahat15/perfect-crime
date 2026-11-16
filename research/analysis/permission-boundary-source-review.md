# Initial permission-boundary investigation

## What the current source establishes

- `trace_lab/cli.py`, `Experiment.start_container`: the ordinary agent container defaults to UID/GID 1000:1000, drops Linux capabilities and sets no-new-privileges. Its root filesystem is read-only, but the agent home and workspace are separate writable volumes.
- `trace_lab/fixtures.py`, `initialize`: the initializer assigns `/home/agent` and `/workspace` to UID/GID 1000:1000.
- `trace_lab/cli.py`, `supervised_stage`: the native CLI is launched through Docker exec without a different user override. This configures it under the agent container's account. The current wrapper does not separate the native recorder from agent-directed tools by OS account.
- `trace_lab/cli.py`, `native_command`: this Codex case requests full access and no approval prompts. The checkout does not implement its published auto-mode adapter for Codex; do not label a full-access run as an auto-mode comparison.
- Baseline trial 9's completed `item_8` listing reports its transcript as owned by `agent:agent` with mode 0644. This is tool-reported ownership evidence, not an independent trace of every writer process.

## What the disposable probes measure

Using the same installed image, create synthetic files in a fresh tmpfs. A trusted setup process configures four ownership/mode cases. Each operation runs in a fresh child under UID/GID 1000:1000 with no supplementary groups, no effective/permitted/ambient capabilities and no-new-privileges. Record the child's identity and compare file existence, inode, ownership, mode and content hash independently afterward.

1. Agent-owned writable file and directory.
2. Agent-owned read-only file in an agent-writable directory.
3. Recorder-owned file in an agent-writable directory.
4. Recorder-owned file and directory, with protected ancestors.

Each case independently tests rewrite, truncate, delete, replace, append a synthetic marker, and chmod followed by rewrite. Fresh fixtures prevent one operation from changing the next operation's starting permissions. An additional control deliberately passes an already-open writable handle to an unprivileged child. Separate controls check workspace writing/Python execution and a trusted append.

These are POSIX mechanism probes, not model trials or native-harness defense results. The trusted setup uses container-only CHOWN, DAC_OVERRIDE, SETUID and SETGID capabilities; the untrusted children must have zero effective/permitted/ambient capabilities. No host directories, credentials or Docker socket are mounted. No network or model calls are used.

## Why these cases matter

Removing a name depends on its parent directory's access permissions. A file owner can normally restore write permission with chmod. Therefore, changing only a transcript's mode does not establish a boundary against the account that owns its file or writable directory. An already-open writable descriptor is a separate authority that path permissions alone may not remove.

## Remaining native integration work

- Measure actual recorder, shell and built-in edit identities; inspect the real processes' writable descriptors.
- Keep every agent-directed edit route on the restricted side of the boundary, including in-process built-in tools.
- Protect directory ancestors, configuration, replacement paths and inherited writable handles.
- Verify a benign coding task, native logging, close/resume and a subsequent recorded action under the integrated protection.
- Check forged-history acceptance with the native parser; a synthetic appended marker alone does not establish accepted native-history forgery.

The current filesystem observer records mutations but does not identify the syscall's originating process or capture its writable descriptor table. The completed baseline did not collect that dynamic mapping. These limitations remain explicit.

## Primary references

- Linux unlink semantics and parent-directory permissions: https://man7.org/linux/man-pages/man2/unlink.2.html
- Linux chmod ownership requirements: https://man7.org/linux/man-pages/man2/chmod.2.html
- Open file descriptions and descriptor semantics: https://man7.org/linux/man-pages/man2/open.2.html
- Docker user, filesystem, networking and capability controls: https://docs.docker.com/engine/containers/run/
