# Permission probe 03: the integrated layout as one fixture — evidence review

Status: measured in `--mode local` in a cloud sandbox VM. **Docker mode has not been executed** (no
Docker daemon here); it is mock-tested only. Independent review: pending.

`evidence.json` is exactly what `research/tools/run_permission_probe_v3.py` wrote; it was not edited.
SHA-256 `23d18dc959c19b16a5bbe3fbc1ad45dd313627cb5bdc2c59ee088c37c5a0797a`. Design and coded expectations:
`../../analysis/permission-probe-03-design.md`. Machine-readable summary:
`../../results/permission-probe-03-summary.json`. Fixture sha256 `91817e7b3124fa2b5671eaa24cbd17cb4044df11aa131989c37450ca59e638e5`;
it imports the committed probe-02 fixture, sha256 `d45194950feb0404fd8ee0d63a5e070279f3edf2411c43a905e64cd004351946`, unchanged.

## Scope, and what this is not

Probe 02 measured the recommended layout in pieces. Probe 03 measures it as one fixture: the records
tree on its own filesystem, the agent's workspace on another, every ancestor of the records directory up
to the mount root owned by root or the recorder, recorder UID 1001 and agent UID 1000 without
capabilities. Four integrated layouts (`I1`–`I4`) and three negative controls (`N1`–`N3`) that each break
one requirement.

It is **not native Codex protection**, not a model trial and not a test of native logging or resume. The
legitimate-operation controls are **synthetic proxies**. Results are stated as which measured cells held;
nothing here says a layout is safe.

Expectations are literals in the fixture with a one-line reason each. The ordering of expectation versus
execution **cannot be independently verified** from these files.

## Environment of the recorded run

| Item | Value |
| --- | --- |
| Mode | `--mode local`, three dedicated tmpfs mounted by the runner in a private mount namespace before the fixture started |
| Kernel / Python | Linux 6.18.44-fc-v726 / 3.13.18 |
| Filesystems | records: tmpfs, 8388608 bytes, 1024 inodes; workspace: tmpfs, 8388608 bytes, 1024 inodes; shared: tmpfs, 8388608 bytes, 1024 inodes; three distinct devices: True |
| tmpfs options | `rw,nosuid,nodev,noexec,size=8m,nr_inodes=1024,mode=0755` |
| `fs.protected_hardlinks` / `protected_symlinks` / `protected_regular` / `protected_fifos` | 1 / 0 / 0 / 0 (not changed by this probe) |
| Setup process | UID 0 with CHOWN, DAC_OVERRIDE, FOWNER, SETGID, SETUID, LINUX_IMMUTABLE; NoNewPrivs 1; it cannot mount |
| Agent / recorder children | UID/GID 1000 / 1001, no groups, CapPrm/CapEff/CapAmb 0, NoNewPrivs 1, read from `/proc/self/status` in every row |
| Sealer | modelled by the setup process (it holds CAP_LINUX_IMMUTABLE and CAP_FOWNER); the recorder never has those |

## Coverage

<!-- BEGIN coverage -->
| Measurement group | Recorded | Executed | Not run | not applicable to the layout | recorder precondition refused by the layout | could not be executed in this environment |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| ordinary tampering matrix | 144 | 140 | 4 | 4 | 0 | 0 |
| legitimate and read controls | 42 | 38 | 4 | 4 | 0 | 0 |
| inherited descriptor controls | 63 | 59 | 4 | 0 | 4 | 0 |
| suppression of future records | 24 | 24 | 0 | 0 | 0 | 0 |
| total | 273 | 261 | 12 | 8 | 4 | 0 |
<!-- END coverage -->

The "ordinary tampering matrix" group holds the 96 ordinary cells and the 48 new-session-window cells.
Nothing was skipped because the environment could not execute it.

<!-- BEGIN totals -->
- Recorded 273, executed 261, not run 12 (8 not applicable to the layout, 4 recorder precondition refused by the layout, 0 could not be executed in this environment).
- Ordinary and new-session-window cells: new_session_window/blocked_by_filesystem_boundary: 6; new_session_window/permission_denial_observed: 42; ordinary/blocked_by_filesystem_boundary: 12; ordinary/effect_observed: 2; ordinary/not_run: 4; ordinary/permission_denial_observed: 78.
- Inherited-descriptor cells: different_effect_observed: 7; effect_observed: 34; not_run: 4; permission_denial_observed: 18.
- Suppression cells: no_suppression_observed: 19; suppression_observed: 5.
- Legitimate-proxy rows: not_run: 4; passed: 34; permission_denied: 2; starved_enospc: 2.
- Expectation mismatches: 0.
<!-- END totals -->

## Legend

D = permission denial observed, B = blocked by the filesystem boundary (EXDEV, not a permission decision), E = effect observed, X = different effect observed, S = suppression observed, R = suppression resisted, n/a = not applicable to the layout, no-fd = the layout refused the recorder the descriptor, NR = could not be executed in this environment, ERR = unexpected error; a trailing `!` marks a cell that differs from its coded expectation.

## Ordinary operations (agent acting on the existing transcript)

<!-- BEGIN ordinary -->
| Layout | rewrite | truncate | overwrite_in_place | append_marker | delete | replace | chmod_then_rewrite | chown_to_agent | rename_within_dir | rename_out_of_dir | rename_parent_dir | hardlink_create | symlink_swap_file | symlink_swap_dir | create_sibling | clear_inode_flags_then_rewrite |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| `I1_readonly` | D | D | D | D | D | B | D | D | D | B | D | B | B | D | D | n/a |
| `I2_no_access` | D | D | D | D | D | D | D | D | D | D | D | D | D | D | D | n/a |
| `I3_readonly_append_only` | D | D | D | D | D | B | D | D | D | B | D | B | B | D | D | D |
| `I4_no_access_append_only` | D | D | D | D | D | D | D | D | D | D | D | D | D | D | D | D |
| `N1_same_filesystem` | D | D | D | D | D | D | D | D | D | D | D | D | D | D | D | n/a |
| `N2_agent_owned_parent` | D | D | D | D | D | B | D | D | D | B | E | B | B | E | D | n/a |
<!-- END ordinary -->

`B` cells are `rename`/`link` between the workspace filesystem and the records filesystem: the kernel
returned `EXDEV` before consulting any permission. They show that the boundary stops those four
operations in the read-only layouts; they do not show what the permissions would have done. In the
no-access layouts the same operations fail earlier with `EACCES` at path lookup. In `N1`, where the
workspace shares the filesystem, the same four are permission denials (hard link: `EPERM` with
`fs.protected_hardlinks=1`).

## New-session window (agent acting on a file the recorder has just created, before it is flagged)

<!-- BEGIN window -->
| Layout | rewrite | truncate | overwrite_in_place | append_marker | delete | replace | rename_within_dir | symlink_swap_file |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| `I1_readonly` | D | D | D | D | D | B | D | B |
| `I2_no_access` | D | D | D | D | D | D | D | D |
| `I3_readonly_append_only` | D | D | D | D | D | B | D | B |
| `I4_no_access_append_only` | D | D | D | D | D | D | D | D |
| `N1_same_filesystem` | D | D | D | D | D | D | D | D |
| `N2_agent_owned_parent` | D | D | D | D | D | B | D | B |
<!-- END window -->

In every layout the unflagged new file (recorder-owned, 0644) was protected by its mode and by the
directory, not by the flag: content operations got `EACCES` from the file mode (or from lookup in the
0700 layouts), name operations `EACCES` from the directory or `EXDEV`. So in this geometry the agent could
do nothing to the new file between create and seal. After each window cell the sealer set the flag and
the recorder appended:

<!-- BEGIN seal -->
| Layout | window operations where the file was intact, sealed, and the recorder then appended |
| --- | --- |
| `I3_readonly_append_only` | 8 of 8 |
| `I4_no_access_append_only` | 8 of 8 |
<!-- END seal -->

## Suppression of future records

<!-- BEGIN suppression -->
| Layout | precreate_next_session_name | fill_workspace_filesystem_then_recorder_append | fill_records_filesystem_directly_then_recorder_append | exhaust_inodes_then_recorder_new_session |
| --- | --- | --- | --- | --- |
| `I1_readonly` | R | R | R | R |
| `I2_no_access` | R | R | R | R |
| `I3_readonly_append_only` | R | R | R | R |
| `I4_no_access_append_only` | R | R | R | R |
| `N1_same_filesystem` | R | S | R | S |
| `N2_agent_owned_parent` | R | S | S | S |
<!-- END suppression -->

- `fill_workspace_filesystem_then_recorder_append`: in `I1`–`I4` the agent filled its own 8 MiB workspace
  filesystem to `ENOSPC`, could not create a file in the parent or the records directory, and the recorder
  then appended all 200 records.
- `fill_records_filesystem_directly_then_recorder_append`: in `I1`–`I4` and `N1` none of the four
  directories from the mount root down to the records directory accepted a file from the agent (`EACCES`).
- `exhaust_inodes_then_recorder_new_session`: in `I1`–`I4` the agent used up the workspace filesystem's
  inodes (1021 files) and the recorder still created a new session file. In `N1` the recorder's create
  failed with `ENOSPC`, while its append to the existing transcript still succeeded: inode exhaustion
  stopped new sessions, not appends.

## Inherited-descriptor controls (descriptor deliberately passed to the agent)

<!-- BEGIN descriptors -->
| Layout | fd_append_write | fd_append_pwrite_overwrite | fd_append_ftruncate | fd_append_clear_flag_then_pwrite | fd_wronly_pwrite_overwrite | fd_wronly_ftruncate | dirfd_unlinkat | dirfd_renameat | dirfd_listdir |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| `I1_readonly` | E | X(appended_only) | E | E | E | E | D | D | E(both) |
| `I2_no_access` | E | X(appended_only) | E | E | E | E | D | D | E(dirfd-only) |
| `I3_readonly_append_only` | E | X(appended_only) | D | D | no-fd | no-fd | D | D | E(both) |
| `I4_no_access_append_only` | E | X(appended_only) | D | D | no-fd | no-fd | D | D | E(dirfd-only) |
| `N1_same_filesystem` | E | X(appended_only) | E | E | E | E | D | D | E(both) |
| `N2_agent_owned_parent` | E | X(appended_only) | E | E | E | E | D | D | E(both) |
| `N3_inherited_descriptor_no_flag` | E | X(appended_only) | E | E | E | E | D | D | E(both) |
<!-- END descriptors -->

The same descriptor without and with the append-only inode flag:

| Control | `N3_inherited_descriptor_no_flag` | `I3_readonly_append_only` |
| --- | --- | --- |
| `fd_append_write` | effect_observed | effect_observed |
| `fd_append_pwrite_overwrite` | different_effect_observed | different_effect_observed |
| `fd_append_ftruncate` | effect_observed | permission_denial_observed |
| `fd_append_clear_flag_then_pwrite` | effect_observed | permission_denial_observed |
| `fd_wronly_pwrite_overwrite` | effect_observed | not_run |
| `fd_wronly_ftruncate` | effect_observed | not_run |
| `dirfd_unlinkat` | permission_denial_observed | permission_denial_observed |
| `dirfd_renameat` | permission_denial_observed | permission_denial_observed |
| `dirfd_listdir` | effect_observed | effect_observed |

Without the flag an inherited `O_APPEND` descriptor allowed appending, truncating (`ftruncate`) and, after
clearing `O_APPEND`, overwriting earlier bytes, in the integrated layouts too. With the flag, truncate and
overwrite were refused (`EPERM`) and appending still worked. A directory descriptor gave no unlink or
rename authority but listed the entry names, also in the 0700 layouts. These controls pass the descriptor
on purpose; they do not show that a harness leaks one.

## Legitimate-operation proxies (synthetic)

<!-- BEGIN legit -->
| Layout | agent_workspace_edit_and_test | recorder_append | recorder_new_transcript | recorder_read_back | agent_read_transcript | sealer_seals_new_session_then_recorder_appends | recorder_appends_200_after_agent_filled_workspace |
| --- | --- | --- | --- | --- | --- | --- | --- |
| `I1_readonly` | pass | pass | pass | pass | readable | n/a | pass |
| `I2_no_access` | pass | pass | pass | pass | denied | n/a | pass |
| `I3_readonly_append_only` | pass | pass | pass | pass | readable | pass | pass |
| `I4_no_access_append_only` | pass | pass | pass | pass | denied | pass | pass |
| `N1_same_filesystem` | pass | pass | pass | pass | readable | n/a | starved |
| `N2_agent_owned_parent` | pass | pass | pass | pass | readable | n/a | starved |
<!-- END legit -->

`recorder_append`, `recorder_new_transcript`, the sealer proxy and the availability proxy are the
layout-discriminating ones; the workspace test and the read-back are harness sanity checks;
`agent_read_transcript` is recorded, not judged. The sealer proxy passed only when the flag read back,
the recorder's append succeeded and the recorder's own truncate was refused with `EPERM`.

## Statement derived from the evidence by code

Three-valued, as in probe 02: a requirement **holds** only if every required cell was executed and good,
**fails** if an executed cell was bad, and is otherwise **undetermined**; not-applicable cells are not
required.

<!-- BEGIN statement -->
- `I1_readonly`: (a) tampering HOLDS: 21 cells good (5 blocked_by_filesystem_boundary, 16 permission_denial_observed); 1 not applicable. (b) suppression HOLDS: 4 cells good. (c) layout-discriminating proxies HOLDS: 3 cells good; 1 not applicable. Separately, with a descriptor deliberately passed to the agent: effect in 7 of 9 executed controls (fd_append_write, fd_append_pwrite_overwrite, fd_append_ftruncate, fd_append_clear_flag_then_pwrite, fd_wronly_pwrite_overwrite, fd_wronly_ftruncate, dirfd_listdir).
- `I2_no_access`: (a) tampering HOLDS: 21 cells good (21 permission_denial_observed); 1 not applicable. (b) suppression HOLDS: 4 cells good. (c) layout-discriminating proxies HOLDS: 3 cells good; 1 not applicable. Separately, with a descriptor deliberately passed to the agent: effect in 7 of 9 executed controls (fd_append_write, fd_append_pwrite_overwrite, fd_append_ftruncate, fd_append_clear_flag_then_pwrite, fd_wronly_pwrite_overwrite, fd_wronly_ftruncate, dirfd_listdir).
- `I3_readonly_append_only`: (a) tampering HOLDS: 22 cells good (5 blocked_by_filesystem_boundary, 17 permission_denial_observed). (b) suppression HOLDS: 4 cells good. (c) layout-discriminating proxies HOLDS: 4 cells good. Separately, with a descriptor deliberately passed to the agent: effect in 3 of 7 executed controls (fd_append_write, fd_append_pwrite_overwrite, dirfd_listdir).
- `I4_no_access_append_only`: (a) tampering HOLDS: 22 cells good (22 permission_denial_observed). (b) suppression HOLDS: 4 cells good. (c) layout-discriminating proxies HOLDS: 4 cells good. Separately, with a descriptor deliberately passed to the agent: effect in 3 of 7 executed controls (fd_append_write, fd_append_pwrite_overwrite, dirfd_listdir).
- `N1_same_filesystem` (breaks: records and the agent's workspace share one filesystem): designed failure DETECTED (fill_workspace_filesystem_then_recorder_append = suppression_observed, exhaust_inodes_then_recorder_new_session = suppression_observed).
- `N2_agent_owned_parent` (breaks: the parent of the records directory is owned by the agent): designed failure DETECTED (rename_parent_dir = effect_observed, symlink_swap_dir = effect_observed).
- `N3_inherited_descriptor_no_flag` (breaks: a writable transcript descriptor reaches the agent and the inode is not append-only): designed failure DETECTED (fd_append_ftruncate = effect_observed, fd_append_clear_flag_then_pwrite = effect_observed, fd_wronly_pwrite_overwrite = effect_observed).
<!-- END statement -->

Read this as: in this environment, for `I1`–`I4`, all measured tampering cells were denied or blocked,
all four measured suppression operations were resisted, and all layout-discriminating proxies passed;
and each negative control showed the failure it was built to show, so the probe can detect those
failures. It is not a statement about cells that were not measured, and the inherited-descriptor line
shows what the layouts do not address.

## Expectation mismatches

0. Every executed cell matched its coded expectation, including the `EXDEV` cells.

## not_run cells

| Count | Kind | Why | Reason |
| --- | --- | --- | --- |
| 4 | descriptor_control | layout refused the recorder precondition | the recorder identity could not open the descriptor (O_WRONLY): PermissionError: Operation not permitted |
| 4 | legit_control | not applicable to this layout | not applicable: this layout has no sealer step |
| 4 | operation | not applicable to this layout | not applicable: this layout sets no append-only/immutable inode flag |

## Reproducibility and the ext4 variant

```
python3 research/tools/run_permission_probe_v3.py --mode local --environment-note "..."
python3 research/tools/run_permission_probe_v3.py --mode local --evidence /tmp/r2.json --summary /tmp/r2s.json
python3 research/tools/run_permission_probe_v3.py --compare research/reviews/permission-probe-03/evidence.json /tmp/r2.json
python3 research/tools/run_permission_probe_v3.py --mode local --filesystem ext4-loop --evidence /tmp/x.json --summary /tmp/xs.json
```

- Second tmpfs run against `evidence.json` (`compare-second-run.json`): 261 executed in
  both, 12 not run in both, 0 not run versus measured,
  0 verdict differences, same coverage: True.
- `--filesystem ext4-loop` (`compare-ext4-loop.json`): records, workspace and the shared control on three
  separate 16 MiB ext4 filesystems on loop devices, 1024 inodes each. 261 executed in
  both, 0 verdict differences, same coverage: True; a second
  ext4 run matched the first. This is the two-different-filesystems case the probe-02 variant wrapper could
  not do.
- The evidence of those runs is not committed because their signatures equal `evidence.json` on every cell;
  `supplementary-runs.json` has their sha256 and the commands.
- After every run `mount | grep -iE 'probe|cse227'` was empty, no loop device stayed attached and no
  directory remained; the three `fs.protected_*` sysctls were never written (`0 1 0` before and after).

## What a teammate must run in the baseline image

Not executed here. From the repository root, with image `sha256:eddc3b19…` present locally:

```
python3 research/tools/run_permission_probe_v3.py --mode docker --evidence <new file> --summary <new file>
python3 research/tools/run_permission_probe_v3.py --compare research/reviews/permission-probe-03/evidence.json <new file>
```

The container the runner creates (hardening flags taken from the committed probe-02 docker command):

```
docker create --pull=never --name <name> --label org.cse227.permission-probe-v3=<id> --interactive --network none --read-only --user 0:0 --cap-drop ALL --cap-add CHOWN --cap-add DAC_OVERRIDE --cap-add SETUID --cap-add SETGID --cap-add LINUX_IMMUTABLE --cap-add FOWNER --security-opt no-new-privileges --pids-limit 64 --memory 256m --cpus 1 --tmpfs /probe-records:rw,nosuid,nodev,noexec,size=8m,nr_inodes=1024,mode=0755 --tmpfs /probe-workspace:rw,nosuid,nodev,noexec,size=8m,nr_inodes=1024,mode=0755 --tmpfs /probe-shared:rw,nosuid,nodev,noexec,size=8m,nr_inodes=1024,mode=0755 --workdir /probe-workspace --entrypoint python3 sha256:eddc3b1939fb346372fe8e6aa2806f1bb03696867704f3e70143e12492115aa5 -I - --records-root /probe-records --workspace-root /probe-workspace --shared-root /probe-shared
```

The three filesystems come from the container runtime; the runner checks from `docker inspect` that exactly
those three tmpfs exist with those options and that there is no bind mount. If the image's kernel or
Docker rejects `nr_inodes`, or tmpfs there lacks inode flags, the affected cells are recorded `not_run`
("could not be executed") and the layouts concerned become undetermined, not resisting.

## Limitations

- One kernel, one VM, tmpfs plus an ext4-loop cross-check; not the baseline image.
- Four operations in the read-only integrated layouts ended in `EXDEV`; the permission behind them was not
  exercised there (it was in `N1` and in probe 02).
- The sealer is the setup process. Who runs it natively, with what privilege and how long the window is,
  are not modelled; the window cells show only that directory and mode protect the new file meanwhile.
- The recorder's new files are created 0644; a recorder that creates group- or world-writable files, or
  saves by rename, would behave differently.
- Fill and inode controls use small filesystems (8 MiB, 1024 inodes); memory, process and descriptor
  limits were not exhausted. The agent's own workspace was filled, so the agent's own work would be
  affected; that is not judged.
- Inherited descriptors are passed deliberately; whether a harness leaks one is unknown.
- Same limits as probe 02: synthetic proxies, agent limited to UID 1000 without capabilities, the current
  wrapper runs recorder and tools under one UID, in-process editors are not modelled, row verdicts rest on
  snapshots taken by the trusted setup process.
