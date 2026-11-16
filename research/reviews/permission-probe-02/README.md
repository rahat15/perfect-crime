# Disposable permission probe 02: evidence review

Status: measured in `--mode local` only. Independent review: a reviewer re-ran this probe and
reproduced 125 cells by hand (no committed verdict wrong, all counts reproduced); a further review
round added the suppression, discriminating-proxy and directory-listing measurements recorded here.
Image-matched `--mode docker` run: **not yet executed** (see "What still has to be run").

`evidence.json` is exactly what `research/tools/run_permission_probe_v2.py` wrote; it was not edited.
SHA-256 `a0df09db4be8f32cea0837dd3135d5e79b198a4cd9e73c8caf61d59af264cb29`. Design and the coded expectations: `../../analysis/permission-probe-02-design.md`.
Machine-readable summary: `../../results/permission-probe-02-summary.json`.

## Scope, and what this is not

Probe 02 extends probe 01. It measures, with synthetic files and explicit syscalls, whether standard
Linux permissions, separate accounts, sticky/setgid directories, inode flags and POSIX ACLs stop an
unprivileged "agent" account (UID/GID 1000, zero capabilities) from deleting, modifying, moving or
redirecting a transcript file, and from suppressing *future* records, while an unprivileged "recorder"
account (UID/GID 1001) can still record and read.

It is **not native Codex protection**, not a model trial, and not a test of native logging or native
session resume. The legitimate-operation and suppression controls are **synthetic proxies**; they show
only whether the access such activity needs is permitted by the layout.

### On "expectations"

Every expected verdict is a literal in `research/tools/permission_probe_v2_fixture.py`, reasoned from
POSIX/Linux semantics, and each evidence file records that fixture's sha256 so a reader can confirm the
expectations it was measured against. These files cannot prove the expectations were written before any
earlier exploratory run (all files were untracked and the fixture ran several times during development).
The genuinely pre-registered measurement is a teammate's `--mode docker` run in the committed baseline
image, performed after this code is committed.

## Environment of the recorded run

| Item | Value |
| --- | --- |
| Mode | `--mode local` (fixture run directly as root in private tmpfs; **not** in baseline image `sha256:eddc3b19...`) |
| Where | cloud sandbox VM; Docker client present but no Docker daemon, so `--mode docker` could not run |
| Kernel | Linux 6.18.44-fc-v470, x86_64 |
| Python | 3.13.18 |
| Probe roots | a 64m private tmpfs for the general layouts; two small dedicated 4m tmpfs for the fill controls; all mounted in the fixture's private mount namespace under the temp dir |
| `fs.protected_hardlinks` | 1 (hard-link results depend on this) |
| `fs.protected_symlinks` / `fs.protected_regular` / `fs.protected_fifos` | 0 / 0 / 0 |
| Setup process caps | CHOWN, DAC_OVERRIDE, FOWNER, SETGID, SETUID, LINUX_IMMUTABLE; NoNewPrivs 1 |
| Agent children | UID/GID 1000 (real/eff/saved), groups [] (or [2000] in the three shared-group layouts), CapPrm/CapEff/CapAmb 0, NoNewPrivs 1 |
| Recorder children | UID/GID 1001, groups [], CapPrm/CapEff/CapAmb 0, NoNewPrivs 1 |

Capability note. Probe 01 used CHOWN, DAC_OVERRIDE, SETUID, SETGID. Probe 02 adds exactly
`CAP_LINUX_IMMUTABLE` (to set `+a`/`+i`) and `CAP_FOWNER` (`FS_IOC_SETFLAGS` on an inode UID 0 no longer
owns after chown). In local mode the runner drops the setup process to that same six-capability set
(bounding, permitted, effective) and sets no-new-privs before it starts, so setup cannot rely on
anything the container lacks; `--full-root-setup` keeps full root and gave identical verdicts. Removing
either extra capability makes the relevant flag layouts `not_run` with the errno, never a guessed result.

## Measured results: layout x operation (agent account acting)

E = effect observed, D = permission denial observed, X = different effect observed, S = suppression observed, R = suppression resisted, n/a = not run (not applicable to the layout), NR = not run (feature unavailable), no-fd = not run (the recorder identity itself could not open that descriptor), E(both)/E(dirfd-only) = names listed via both the path and the directory descriptor / only the descriptor, ERR = unexpected error; a trailing `!` marks a cell that differs from its coded expectation.

`hardlink_create` and `create_sibling` do not change the transcript and are reported as their own
categories, not as tampering. The other fourteen operations are the "tampering operations". Each row
also records `failed_step` (the first refused syscall) and `denial_class` (EACCES = a discretionary
mode/ACL check; EPERM = an ownership, sticky-bit, inode-flag, protected_hardlinks or capability rule).

<!-- BEGIN matrix -->
| Layout | rewrite | truncate | overwrite_in_place | append_marker | delete | replace | chmod_then_rewrite | chown_to_agent | rename_within_dir | rename_out_of_dir | rename_parent_dir | hardlink_create | symlink_swap_file | symlink_swap_dir | create_sibling | clear_inode_flags_then_rewrite |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| `agent_owned_writable` | E | E | E | E | E | E | E | n/a | E | E | E | E | E | E | E | n/a |
| `recorder_file_agent_writable_dir` | D | D | D | D | E | E | D | D | E | E | D | D | E | D | E | n/a |
| `sticky_1777_dir_recorder_file` | D | D | D | D | D | D | D | D | D | D | D | D | D | D | E | n/a |
| `sticky_1770_shared_group_dir` | D | D | D | D | D | D | D | D | D | D | D | D | D | D | E | n/a |
| `setgid_2770_shared_group_file_0640` | D | D | D | D | E | E | D | D | E | E | D | D | E | D | E | n/a |
| `setgid_2770_shared_group_file_0660` | E | E | E | E | E | E | D | D | E | E | D | E | E | D | E | n/a |
| `recorder_owned_agent_readonly` | D | D | D | D | D | D | D | D | D | D | D | D | D | D | D | n/a |
| `recorder_owned_no_agent_access` | D | D | D | D | D | D | D | D | D | D | D | D | D | D | D | n/a |
| `recorder_dir_in_agent_owned_parent` | D | D | D | D | D | D | D | D | D | D | E | D | D | E | D | n/a |
| `append_only_same_account` | D | D | D | E | D | D | D | n/a | D | D | E | D | D | E | E | D |
| `append_only_file_and_dir_same_account` | D | D | D | E | D | D | D | n/a | D | D | D | D | D | D | E | D |
| `append_only_recorder_owned` | D | D | D | D | D | D | D | D | D | D | D | D | D | D | D | D |
| `immutable_recorder_owned` | D | D | D | D | D | D | D | D | D | D | D | D | D | D | D | D |
| `acl_agent_read_only` | D | D | D | D | D | D | D | D | D | D | D | D | D | D | D | n/a |
| `acl_agent_dir_write_file_read` | D | D | D | D | E | E | D | D | E | E | D | D | E | D | E | n/a |
<!-- END matrix -->

## Totals

<!-- BEGIN totals -->
- Ordinary cells: 240. effect_observed: 53; not_run: 14; permission_denial_observed: 173.
- Layout-discriminating proxy controls: 24. passed: 22; permission_denied: 2.
- Harness sanity checks (same in every layout): 36.
- Inherited-descriptor controls: 135. different_effect_observed: 14; effect_observed: 83; not_run: 12; permission_denial_observed: 26.
- Suppression-of-future-records controls: 45. no_suppression_observed: 10; not_run: 2; suppression_observed: 33.
- Expectation mismatches: 0.
<!-- END totals -->

Ordinary `not_run` (14) are all "not applicable": 11 x `clear_inode_flags_then_rewrite` on layouts
without an inode flag, 3 x `chown_to_agent` where the transcript is already agent-owned.

## Legitimate-operation proxies

Only two of the five proxies can depend on the layout: `recorder_append` and `recorder_new_transcript`
written by a *separate* recorder account. The other three are **harness sanity checks** that are the
same in every layout: `agent_workspace_edit_and_test` (workspace is agent-owned 0755 everywhere),
`recorder_read_back` (the recorder reads a file it owns), and `agent_read_transcript` (recorded, not
judged). In the three shared-account layouts the recorder *is* uid 1000, so there even the two
write proxies are sanity checks. The discriminating count is therefore 24 (2 controls x 12
separate-account layouts), of which 22 pass and 2 are denied.

Layout-discriminating proxies (separate recorder account):

<!-- BEGIN legit_discriminating -->
| Layout | recorder_append | recorder_new_transcript |
| --- | --- | --- |
| `agent_owned_writable` | pass | pass |
| `recorder_file_agent_writable_dir` | pass | denied |
| `sticky_1777_dir_recorder_file` | pass | pass |
| `sticky_1770_shared_group_dir` | pass | pass |
| `setgid_2770_shared_group_file_0640` | pass | pass |
| `setgid_2770_shared_group_file_0660` | pass | pass |
| `recorder_owned_agent_readonly` | pass | pass |
| `recorder_owned_no_agent_access` | pass | pass |
| `recorder_dir_in_agent_owned_parent` | pass | pass |
| `append_only_same_account` | pass | pass |
| `append_only_file_and_dir_same_account` | pass | pass |
| `append_only_recorder_owned` | pass | pass |
| `immutable_recorder_owned` | denied | pass |
| `acl_agent_read_only` | pass | pass |
| `acl_agent_dir_write_file_read` | pass | pass |
<!-- END legit_discriminating -->

Harness sanity checks (same in every layout; `agent_read_transcript` is recorded, not judged):

<!-- BEGIN legit_sanity -->
| Layout | agent_workspace_edit_and_test | recorder_read_back | agent_read_transcript |
| --- | --- | --- | --- |
| `agent_owned_writable` | pass | pass | readable |
| `recorder_file_agent_writable_dir` | pass | pass | readable |
| `sticky_1777_dir_recorder_file` | pass | pass | readable |
| `sticky_1770_shared_group_dir` | pass | pass | readable |
| `setgid_2770_shared_group_file_0640` | pass | pass | readable |
| `setgid_2770_shared_group_file_0660` | pass | pass | readable |
| `recorder_owned_agent_readonly` | pass | pass | readable |
| `recorder_owned_no_agent_access` | pass | pass | denied |
| `recorder_dir_in_agent_owned_parent` | pass | pass | readable |
| `append_only_same_account` | pass | pass | readable |
| `append_only_file_and_dir_same_account` | pass | pass | readable |
| `append_only_recorder_owned` | pass | pass | readable |
| `immutable_recorder_owned` | pass | pass | readable |
| `acl_agent_read_only` | pass | pass | readable |
| `acl_agent_dir_write_file_read` | pass | pass | readable |
<!-- END legit_sanity -->

Both discriminating denials were expected: `recorder_file_agent_writable_dir` cannot create a new
transcript (`EACCES`; the directory is agent-owned), and `immutable_recorder_owned` cannot append
(`EPERM`; immutable). `agent_read_transcript` is `denied` only in `recorder_owned_no_agent_access`.

## Suppression of future records (availability; its own category)

Tampering with existing bytes is not the only risk. `precreate_next_session_name`: the agent first
creates the predictable next transcript name, then the recorder's exclusive create fails. Two `fill`
controls: the agent fills a small dedicated tmpfs until ENOSPC, then the recorder tries to append 200
records. `S` = suppression observed, `R` = resisted, measured by a child dropped to the recorder
identity. The `fill` controls were measured with `fs.protected_regular=0`.

<!-- BEGIN suppression -->
| Layout | precreate_next_session_name | fill_filesystem_then_recorder_append | fill_filesystem_then_recorder_append_separate_fs |
| --- | --- | --- | --- |
| `agent_owned_writable` | S | S | S |
| `recorder_file_agent_writable_dir` | S | S | S |
| `sticky_1777_dir_recorder_file` | S | S | S |
| `sticky_1770_shared_group_dir` | S | S | S |
| `setgid_2770_shared_group_file_0640` | S | S | S |
| `setgid_2770_shared_group_file_0660` | S | S | S |
| `recorder_owned_agent_readonly` | R | S | R |
| `recorder_owned_no_agent_access` | R | S | R |
| `recorder_dir_in_agent_owned_parent` | R | S | S |
| `append_only_same_account` | S | S | S |
| `append_only_file_and_dir_same_account` | S | S | S |
| `append_only_recorder_owned` | R | S | R |
| `immutable_recorder_owned` | R | n/a | n/a |
| `acl_agent_read_only` | R | S | R |
| `acl_agent_dir_write_file_read` | S | S | S |
<!-- END suppression -->

## Which layouts actually protect (measured on these synthetic proxies only)

Layouts that denied every one of the fourteen measured tampering operations **and** kept all four
judged proxies working:

<!-- BEGIN protecting -->
- `sticky_1777_dir_recorder_file`
- `sticky_1770_shared_group_dir`
- `recorder_owned_agent_readonly`
- `recorder_owned_no_agent_access`
- `append_only_recorder_owned`
- `acl_agent_read_only`
<!-- END protecting -->

Layouts that, in addition, resisted **both** fill suppression operations and precreate:

<!-- BEGIN protecting_strict -->
- (none)
<!-- END protecting_strict -->

The stricter list is **empty**. Every one of the six tamper-resistant layouts is defeated by the
shared-filesystem disk-fill: whenever the records tree and the agent's workspace share one filesystem,
the agent starves the recorder (ENOSPC) regardless of ownership or mode. Only separating filesystems
helps (the separate-fs fill is `R` for the recorder-owned layouts), and even then the records
filesystem needs a quota the agent cannot exhaust. Further measured qualifications:

- In both sticky layouts the agent can still create its own sibling file in the records directory
  (`create_sibling` = E), and `precreate_next_session_name` = S there.
- `recorder_owned_no_agent_access` is the only layout where the agent account cannot read the
  transcript; but an inherited directory descriptor still leaks the entry listing there
  (`dirfd_listdir` = E(dirfd-only)).
- Where the parent of the records directory is agent-owned
  (`recorder_dir_in_agent_owned_parent`), the recorder-owned 0755/0644 directory and file were
  bypassed by renaming the directory and swapping a symlink in its place (`rename_parent_dir` = E,
  `symlink_swap_dir` = E): ancestors must be protected too.
- The six protecting layouts rely on the recorder being a different account; with a shared account
  (`agent_owned_writable`) every tampering operation succeeded.

## Inherited-descriptor controls

The descriptor is opened by a helper dropped to the recorder identity and deliberately passed to the
agent child (layout recorded in every row). `fd_append_*`: `O_WRONLY|O_APPEND`; `fd_wronly_*`:
`O_WRONLY`; `dirfd_*`: `O_RDONLY|O_DIRECTORY` on the records directory.

<!-- BEGIN descriptors -->
| Layout | fd_append_write | fd_append_pwrite_overwrite | fd_append_ftruncate | fd_append_clear_flag_then_pwrite | fd_wronly_pwrite_overwrite | fd_wronly_ftruncate | dirfd_unlinkat | dirfd_renameat | dirfd_listdir |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| `agent_owned_writable` | E | X(appended_only) | E | E | E | E | E | E | E(both) |
| `recorder_file_agent_writable_dir` | E | X(appended_only) | E | E | E | E | E | E | E(both) |
| `sticky_1777_dir_recorder_file` | E | X(appended_only) | E | E | E | E | D | D | E(both) |
| `sticky_1770_shared_group_dir` | E | X(appended_only) | E | E | E | E | D | D | E(both) |
| `setgid_2770_shared_group_file_0640` | E | X(appended_only) | E | E | E | E | E | E | E(both) |
| `setgid_2770_shared_group_file_0660` | E | X(appended_only) | E | E | E | E | E | E | E(both) |
| `recorder_owned_agent_readonly` | E | X(appended_only) | E | E | E | E | D | D | E(both) |
| `recorder_owned_no_agent_access` | E | X(appended_only) | E | E | E | E | D | D | E(dirfd-only) |
| `recorder_dir_in_agent_owned_parent` | E | X(appended_only) | E | E | E | E | D | D | E(both) |
| `append_only_same_account` | E | X(appended_only) | D | D | no-fd | no-fd | D | D | E(both) |
| `append_only_file_and_dir_same_account` | E | X(appended_only) | D | D | no-fd | no-fd | D | D | E(both) |
| `append_only_recorder_owned` | E | X(appended_only) | D | D | no-fd | no-fd | D | D | E(both) |
| `immutable_recorder_owned` | no-fd | no-fd | no-fd | no-fd | no-fd | no-fd | D | D | E(both) |
| `acl_agent_read_only` | E | X(appended_only) | E | E | E | E | D | D | E(both) |
| `acl_agent_dir_write_file_read` | E | X(appended_only) | E | E | E | E | E | E | E(both) |
<!-- END descriptors -->

- An inherited `O_APPEND` descriptor let the agent append a fabricated record in every layout where the
  recorder could open one, including 0700/0600.
- `pwrite` at offset 0 on an `O_APPEND` descriptor appended rather than overwriting (`X(appended_only)`).
- `O_APPEND` did **not** protect earlier bytes: `ftruncate(fd,0)` emptied the transcript and
  `fcntl(F_SETFL)` clearing `O_APPEND` then `pwrite` overwrote the leading bytes, in every layout without
  the append-only inode flag; with the flag both were `EPERM`.
- An inherited `O_WRONLY` descriptor allowed overwrite and truncation wherever the recorder could open one.
- `dirfd_unlinkat`/`dirfd_renameat` gave no extra name-change authority (they matched the path-based
  `delete`/`rename_within_dir` of the layout, failing at the same step). But `dirfd_listdir` shows a
  directory descriptor **does** leak the entry listing: the agent read the names in all 15 layouts, and in
  `recorder_owned_no_agent_access` it is the only way to read them (the path `listdir` is `EACCES`).
- `no-fd` cells (12): the recorder identity itself could not open the descriptor - `O_WRONLY` without
  `O_APPEND` on the three append-only layouts and the immutable layout, and `O_WRONLY|O_APPEND` on the
  immutable layout; all `EPERM`.

These controls pass the descriptor on purpose; they do not show that Codex or the wrapper leaks one.

## Expectation mismatches

None. All 226 executed ordinary cells, 75 legitimate-proxy rows, 123 executed descriptor rows and 43
executed suppression rows matched the coded expectations. The hard-link expectation is conditional on
`fs.protected_hardlinks`; only the value 1 was measured, so the "sysctl = 0" branch is untested.

## not_run cells

| Count | Kind | Reason |
| --- | --- | --- |
| 11 | operation | not applicable: layout sets no inode flag (`clear_inode_flags_then_rewrite`) |
| 3 | operation | not applicable: transcript already agent-owned (`chown_to_agent`) |
| 8 | descriptor control | recorder could not open `O_WRONLY` (EPERM): append-only and immutable layouts |
| 4 | descriptor control | recorder could not open `O_WRONLY|O_APPEND` (EPERM): immutable layout |
| 2 | suppression control | not applicable: immutable transcript cannot be appended even on an empty filesystem (both fill variants) |

No cell was skipped for a missing filesystem feature; the tmpfs supported inode flags and the ACL xattr,
which were set via `os.setxattr("system.posix_acl_access")` (no `setfacl` binary is installed).

## Reproducibility check

Run from the repository root as root:

```
python3 research/tools/run_permission_probe_v2.py --mode local --overwrite --environment-note "..."
python3 research/tools/run_permission_probe_v2.py --mode local --evidence /tmp/run2.json --summary /tmp/run2-sum.json --overwrite
python3 research/tools/run_permission_probe_v2.py --compare research/reviews/permission-probe-02/evidence.json /tmp/run2.json
```

The comparison reported `identical_verdicts: true` over all 495 measurements (verdict, outcome and errno;
inode numbers, paths and timestamps differ between runs) and `environment_identical: true`. `--compare`
prints the two environments side by side and reports not_run-vs-measured differences separately from
verdict differences. Two committed variants are referenced below. After each run `mount | grep -i probe`
was empty and no probe directory remained (the fixture runs under a private mount namespace with
PR_SET_PDEATHSIG, and the runner installs a SIGTERM handler, so an interrupted run leaks nothing).

## Committed supplementary runs

- `evidence-ext4.json` (+ `compare-ext4.json`): the general layouts run on an ext4 scratch directory
  instead of tmpfs (`--local-scratch-parent /tmp`). Identical **verdicts**; the 28 fill cells are
  `not_run` there because that mode provides no dedicated size-limited tmpfs, which `compare-ext4.json`
  records under `not_run_vs_measured_differences`.
- `evidence-full-root-setup.json` (+ `compare-full-root-setup.json`): the setup process keeps root's
  full capability set (`--full-root-setup`). Fully identical verdicts; only the recorded setup
  capabilities differ.

## What still has to be run

`--mode docker` is implemented and its command construction, inspection checks and cleanup are unit
tested with mocks, but it has **never been executed**: this machine has no Docker daemon. A teammate with
the baseline image must run, from the repository root:

```
python3 research/tools/run_permission_probe_v2.py --mode docker --evidence <new path> --summary <new path>
python3 research/tools/run_permission_probe_v2.py --compare research/reviews/permission-probe-02/evidence.json <new path>
```

It defaults to probe 01's image id (`sha256:eddc3b19...`) and never pulls. On a kernel whose tmpfs lacks
inode-flag support the four flag layouts become `not_run`; the runner prints that explicitly. The fill
controls need dedicated small tmpfs mounts, which the unprivileged container cannot create, so in docker
mode they are `not_run` with a reason - the fill results stand on the local run only.

## Limitations

- Synthetic files and syscalls; not native transcript protection, forged-history acceptance, native
  logging or resume.
- The current wrapper runs the recorder and tools under one UID; the separate-recorder layouts do not
  exist in it yet.
- In-process built-in editors act with the recorder's own authority and are not modelled.
- Whether a real harness leaks a writable or directory descriptor to tool processes is unknown.
- Availability (disk exhaustion, name pre-creation) is only partly a permissions question; the fill
  result depends on filesystem layout and per-filesystem quotas, and the probe's ENOSPC timing is its
  small tmpfs, not production.
- `precreate` was measured with `fs.protected_regular=0`; `protected_regular=1`/`2` may refuse the
  recorder's `O_CREAT|O_APPEND` onto an agent-owned file in a sticky directory, which this run did not
  exercise.
- For recorder-owned flag layouts the hard-link EPERM cannot be attributed to the sysctl or the flag
  separately; the same-account append-only layouts attribute it to the flag.
- One kernel, tmpfs plus a committed ext4 cross-check, a non-image environment. overlayfs, bind volumes,
  user namespaces, rootless Docker, LSMs and idmapped mounts were not measured.
- Only UID/GID 1000 without capabilities was tested as the agent.
- Row verdicts rest on snapshots taken by the trusted setup process; a measurement by the probe, not an
  independent forensic audit.
