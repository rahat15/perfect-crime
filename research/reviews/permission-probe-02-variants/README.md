# Permission probe 02 variants: evidence review

Status: measured locally in a cloud sandbox VM (kernel 6.18.44-fc-v470, Python 3.13.18); **not** the
baseline Docker image and no Docker daemon was available here. The baseline-image run of the unchanged
probe is the teammate's package in `../permission-probe-02-docker/`; this directory was regenerated after
the aggregation correction described in `../permission-probe-02/README.md`, with unchanged measurements. Independent review: pending.

Probe 02 (`../permission-probe-02/`) was re-run **unchanged** under filesystem and sysctl variants by
`research/tools/run_permission_probe_v2_variants.py`, which imports the committed fixture
(sha256 `d45194950feb0404fd8ee0d63a5e070279f3edf2411c43a905e64cd004351946`) and runner (sha256 `038b3783e6dd14315a99d179d209c87585c35a741582e523a9fa3252f50c1201`) and only changes the
environment around them. Every variant is compared with the committed evidence
`research/reviews/permission-probe-02/evidence.json` (sha256 `8e81ab4e30f86c1939e50cc2ead0a6675d6d00c616b62f993452e1924d78188a`) using the committed runner's `--compare`.
Machine-readable record: `variants-summary.json`. Wrapper sha256 for all recorded variants:
`83af1b954e90abc85e3af55aa6d913c52cee1dc5f72a3618c19aa01042acf099`.

## Scope, and what this is not

Synthetic POSIX/Linux mechanism measurements with the same unprivileged agent (UID 1000) and recorder
(UID 1001) children as probe 02. It is **not native Codex protection**, not a model trial and not a test
of native logging or resume. "Closer to how the harness stores state" means only that the probe root sat
on overlayfs, on a bind mount, or on ext4 instead of tmpfs; nothing was run inside Docker.

### Predictions

For every variant the wrapper holds, as data, the cells predicted to differ from the committed evidence
with a one-line reason from kernel documentation semantics (`VARIANTS[...]["predicted_differences"]`,
`prediction_basis`, and `EFFECT_REFUSED_WHEN` for the effect controls). The wrapper sha256 above is recorded
in every variant record. The ordering of prediction versus execution
**cannot be independently verified** from these files: the wrapper was untracked while it was developed and the variants were run
more than once. Differences are reported as measured; none was adjusted.

## Variants and results

| Variant | Status | Filesystem of the layouts | protected_regular / hardlinks / symlinks during run | Recorded / executed / not run | Executed in both | Not run in both | Not run vs measured | Verdict changed | Same verdict, other detail changed | Prediction misses | Second run vs first | Full evidence committed |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| `wrapper_control_tmpfs` | executed | tmpfs | 0/1/0 | 495 / 467 / 28 | 467 | 28 | 0 | 0 | 0 | 0 | same coverage, 0 differences (467 executed in both) | no |
| `overlayfs_on_tmpfs` | executed | overlay | 0/1/0 | 495 / 467 / 28 | 467 | 28 | 0 | 0 | 0 | 0 | same coverage, 0 differences (467 executed in both) | no |
| `overlayfs_on_ext4` | executed | overlay | 0/1/0 | 495 / 467 / 28 | 467 | 28 | 0 | 0 | 0 | 0 | same coverage, 0 differences (467 executed in both) | no |
| `bind_mount_ext4` | executed | ext4 | 0/1/0 | 495 / 467 / 28 | 467 | 28 | 0 | 0 | 0 | 0 | same coverage, 0 differences (467 executed in both) | no |
| `ext4_scratch_with_fill` | executed | ext4 | 0/1/0 | 495 / 467 / 28 | 467 | 28 | 0 | 0 | 0 | 0 | same coverage, 0 differences (467 executed in both) | no |
| `protected_regular_1` | executed | tmpfs | 1/1/0 | 495 / 467 / 28 | 467 | 28 | 0 | 0 | 0 | 0 | same coverage, 0 differences (467 executed in both) | no |
| `protected_regular_2` | executed | tmpfs | 2/1/0 | 495 / 467 / 28 | 467 | 28 | 0 | 0 | 0 | 0 | same coverage, 0 differences (467 executed in both) | no |
| `protected_hardlinks_0` | executed | tmpfs | 0/0/0 | 495 / 467 / 28 | 467 | 28 | 0 | 8 | 0 | 0 | same coverage, 0 differences (467 executed in both) | yes |
| `protected_symlinks_1` | executed | tmpfs | 0/1/1 | 495 / 467 / 28 | 467 | 28 | 0 | 0 | 0 | 0 | same coverage, 0 differences (467 executed in both) | no |

"Executed in both", "Not run in both" and "Not run vs measured" compare each variant with the committed
local evidence, cell by cell; verdicts are compared only among cells executed in both. The 28 cells not run
in both are the same in every variant: 16 not applicable to the layout and 12 where the layout refused the
recorder the descriptor; none is a cell the environment could not execute. "Verdict changed" and "Same
verdict, other detail changed" (errno or outcome only) count cells executed in both whose signature
differs. "Prediction misses" = differences that were not predicted plus predicted differences that did not
occur. Each executed variant was run twice; the second run was compared with the first with the committed
runner's `--compare`.

Not executed:

- `bind_mount_separate_records_workspace`: not_run: the committed fixture places the agent workspace next to the records tree under ONE probe root for every ordinary, legitimate-proxy and descriptor measurement; only the two fill controls accept a separate workspace filesystem, and those must be dedicated tmpfs mounts of at most 8 MiB (fixture.fill_root_problem). Putting records and workspace on different bind-mounted filesystems for the ordinary operations (where rename_out_of_dir, replace, hardlink_create and the symlink swaps would cross a filesystem boundary) therefore needs a change to the frozen fixture, which was not made. The separate-filesystem case IS exercised for the fill control in bind_mount_ext4, where the two fill filesystems are separate bind mounts.

What each variant mounted (from `/proc/self/mountinfo`, recorded per variant in the summary):

- `wrapper_control_tmpfs`: probe = tmpfs; fill-records = tmpfs; fill-workspace = tmpfs; effects = tmpfs
- `overlayfs_on_tmpfs`: overlay-backing = tmpfs; probe = overlay; fill-records = tmpfs; fill-workspace = tmpfs; effects = tmpfs
- `overlayfs_on_ext4`: probe = overlay; fill-records = tmpfs; fill-workspace = tmpfs; effects = tmpfs; overlay lower/upper/work on ext4 directories
- `bind_mount_ext4`: probe = ext4 (bind of bind-source); fill-records-source = tmpfs; fill-records = tmpfs; fill-workspace-source = tmpfs; fill-workspace = tmpfs; effects = tmpfs
- `ext4_scratch_with_fill`: fill-records = tmpfs; fill-workspace = tmpfs; effects = tmpfs; probe root is a plain directory on ext4
- `protected_regular_1`: probe = tmpfs; fill-records = tmpfs; fill-workspace = tmpfs; effects = tmpfs
- `protected_regular_2`: probe = tmpfs; fill-records = tmpfs; fill-workspace = tmpfs; effects = tmpfs
- `protected_hardlinks_0`: probe = tmpfs; fill-records = tmpfs; fill-workspace = tmpfs; effects = tmpfs
- `protected_symlinks_1`: probe = tmpfs; fill-records = tmpfs; fill-workspace = tmpfs; effects = tmpfs

In every variant the fixture's setup process had exactly CHOWN, DAC_OVERRIDE, FOWNER, LINUX_IMMUTABLE,
SETGID, SETUID and no-new-privs (the committed runner's restriction), and inode flags and the POSIX ACL
xattr were supported on every probe root, including both overlay mounts, so **no cell became not_run**
in any variant. `ext4_scratch_with_fill` measured the 28 fill cells that were not_run in the committed
`evidence-ext4.json`, with the same verdicts as the committed tmpfs run.

## The only verdict differences: `protected_hardlinks_0`

| Layout | Operation | Committed (protected_hardlinks=1) | Variant (protected_hardlinks=0) | Predicted |
| --- | --- | --- | --- | --- |
| `acl_agent_dir_write_file_read` | `hardlink_create` | permission_denial_observed, errno 1 (EPERM) | effect_observed, errno None | yes |
| `acl_agent_read_only` | `hardlink_create` | permission_denial_observed, errno 1 (EPERM) | effect_observed, errno None | yes |
| `recorder_dir_in_agent_owned_parent` | `hardlink_create` | permission_denial_observed, errno 1 (EPERM) | effect_observed, errno None | yes |
| `recorder_file_agent_writable_dir` | `hardlink_create` | permission_denial_observed, errno 1 (EPERM) | effect_observed, errno None | yes |
| `recorder_owned_agent_readonly` | `hardlink_create` | permission_denial_observed, errno 1 (EPERM) | effect_observed, errno None | yes |
| `setgid_2770_shared_group_file_0640` | `hardlink_create` | permission_denial_observed, errno 1 (EPERM) | effect_observed, errno None | yes |
| `sticky_1770_shared_group_dir` | `hardlink_create` | permission_denial_observed, errno 1 (EPERM) | effect_observed, errno None | yes |
| `sticky_1777_dir_recorder_file` | `hardlink_create` | permission_denial_observed, errno 1 (EPERM) | effect_observed, errno None | yes |

All eight were predicted (they are exactly the cells the committed fixture codes as sysctl-dependent) and
match the fixture's own expectation for the sysctl value 0. In each, the independent snapshot shows the
transcript unchanged (same inode and hash, still recorder-owned) with link count 2 and a second name
`workspace/hardlink.jsonl`. A hard link gives the agent no write access; it is a second name that keeps
the inode alive and, in the 0755/0644 layouts the agent could read anyway, nothing new to read. The 0700
layout (EACCES at lookup) and the append-only and immutable inodes (EPERM) stayed denied, which separates
the inode flag from the sysctl as the cause there: the committed README said that could not be told apart.
Hard-link creation is not counted as tampering, so the layout lists below do not change.

## Layout lists and suppression table, per variant

Recomputed from each variant's own evidence by `layout_lists()`, which uses the runner's three-valued
`protection_assessment`: a layout **holds** a requirement only if every required cell was executed with the
good verdict, **fails** if an executed cell had the bad verdict, and is **undetermined** (never "resisting")
if a required cell was not executed. List A uses the layout-discriminating proxies (recorder append and new
transcript by a separate recorder account) rather than all judged proxies; for the committed evidence its
"holds" list equals the runner's.

Committed local probe 02 (`../permission-probe-02/evidence.json`):

| List | holds | fails (determined) | undetermined |
| --- | --- | --- | --- |
| A: every tampering operation denied and the layout-discriminating proxies kept | `sticky_1777_dir_recorder_file`, `sticky_1770_shared_group_dir`, `recorder_owned_agent_readonly`, `recorder_owned_no_agent_access`, `append_only_recorder_owned`, `acl_agent_read_only` | `agent_owned_writable`, `recorder_file_agent_writable_dir`, `setgid_2770_shared_group_file_0640`, `setgid_2770_shared_group_file_0660`, `recorder_dir_in_agent_owned_parent`, `append_only_same_account`, `append_only_file_and_dir_same_account`, `immutable_recorder_owned`, `acl_agent_dir_write_file_read` | (none) |
| B: of A.holds, also resist every suppression operation (precreate, shared-filesystem fill, separate-filesystem fill) | (none) | `sticky_1777_dir_recorder_file`, `sticky_1770_shared_group_dir`, `recorder_owned_agent_readonly`, `recorder_owned_no_agent_access`, `append_only_recorder_owned`, `acl_agent_read_only` | (none) |
| C: of A.holds, also resist precreate and the separate-filesystem fill | `recorder_owned_agent_readonly`, `recorder_owned_no_agent_access`, `append_only_recorder_owned`, `acl_agent_read_only` | `sticky_1777_dir_recorder_file`, `sticky_1770_shared_group_dir` | (none) |

The other nine layouts fail list A (a tampering operation succeeded or a discriminating proxy was denied).

| Run | Lists A, B, C (holds, fails and undetermined) equal the committed local run | Layouts undetermined in any list | Suppression table equals committed |
| --- | --- | --- | --- |
| `wrapper_control_tmpfs` | yes | 0 | yes |
| `overlayfs_on_tmpfs` | yes | 0 | yes |
| `overlayfs_on_ext4` | yes | 0 | yes |
| `bind_mount_ext4` | yes | 0 | yes |
| `ext4_scratch_with_fill` | yes | 0 | yes |
| `protected_regular_1` | yes | 0 | yes |
| `protected_regular_2` | yes | 0 | yes |
| `protected_hardlinks_0` | yes | 0 | yes |
| `protected_symlinks_1` | yes | 0 | yes |

Every required cell was executed in every variant, including both disk-fill cells, so no layout is
undetermined anywhere in this directory. That is not true of the Docker run in
`../permission-probe-02-docker/`: there the fill cells were not executed, and under the same rule the four
layouts in "C holds" above are undetermined for lists B and C (see `../permission-probe-02/README.md`,
"Docker validation and aggregation correction"). Nothing in this directory is a Docker result.

Suppression table (identical in the committed run and in all 9 executed variants; S = suppression
observed, R = resisted, n/a = not applicable):

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

So in every variant: six layouts hold list A; none holds list B, and that is determined, because in all
six the shared-filesystem fill was executed and the recorder was starved (the two sticky layouts also fail
on precreate); four hold list C. Overlayfs, a bind mount, ext4 and the three sysctls changed none of this.

## Sysctl effect controls (supplementary, not part of the probe-02 matrix)

`protected_regular` and `protected_symlinks` produced no difference in the probe-02 matrix, as predicted:
the one probe step they could touch (the recorder's `O_CREAT|O_APPEND` onto the agent's pre-created
next-session file) is already refused by the file's 0644 mode, and probe 02 never gets a symlink into a
sticky directory. To show that the sysctls were really in effect and what they do change, the wrapper ran
ten small effect controls per variant (90 of 90 rows matched their prediction): in a sticky
directory owned by the recorder, the agent plants an entry named like the next session (a world-writable
regular file, or a symlink to a world-writable file in its workspace) and the recorder opens that name.

| Directory / control | `wrapper_control_tmpfs` | `protected_regular_1` | `protected_regular_2` | `protected_symlinks_1` | `protected_hardlinks_0` |
| --- | --- | --- | --- | --- | --- |
| sticky_1777 / regular_0666_recorder_o_creat_append | appended into agent file | **refused EACCES** | **refused EACCES** | appended into agent file | appended into agent file |
| sticky_1777 / regular_0666_recorder_append_without_o_creat | appended into agent file | appended into agent file | appended into agent file | appended into agent file | appended into agent file |
| sticky_1777 / regular_0666_recorder_o_creat_excl | refused EEXIST | refused EEXIST | refused EEXIST | refused EEXIST | refused EEXIST |
| sticky_1777 / symlink_recorder_o_creat_append | appended into agent file | appended into agent file | appended into agent file | **refused EACCES** | appended into agent file |
| sticky_1777 / symlink_recorder_o_creat_excl | refused EEXIST | refused EEXIST | refused EEXIST | refused EEXIST | refused EEXIST |
| sticky_1770_shared_group / regular_0666_recorder_o_creat_append | appended into agent file | appended into agent file | **refused EACCES** | appended into agent file | appended into agent file |
| sticky_1770_shared_group / regular_0666_recorder_append_without_o_creat | appended into agent file | appended into agent file | appended into agent file | appended into agent file | appended into agent file |
| sticky_1770_shared_group / regular_0666_recorder_o_creat_excl | refused EEXIST | refused EEXIST | refused EEXIST | refused EEXIST | refused EEXIST |
| sticky_1770_shared_group / symlink_recorder_o_creat_append | appended into agent file | appended into agent file | appended into agent file | appended into agent file | appended into agent file |
| sticky_1770_shared_group / symlink_recorder_o_creat_excl | refused EEXIST | refused EEXIST | refused EEXIST | refused EEXIST | refused EEXIST |

Effect controls in the four filesystem variants: identical to the control column.

Reading: with the defaults on this machine a recorder that opens a predictable name with `O_CREAT` but
without `O_EXCL` in a sticky directory writes its records into a file the agent owns, or through the
agent's symlink into the agent's workspace. `protected_regular=1` stops the first in the world-writable
sticky directory and `=2` also in the group-writable one; `protected_symlinks=1` stops the second in the
world-writable sticky directory only. Opening without `O_CREAT` is never stopped, and `O_CREAT|O_EXCL`
fails with EEXIST in every setting, so these sysctls turn a silent redirect into a refusal but the
recorder still cannot create its session under that name: the precreate suppression verdict is unchanged.

## Evidence files and how to regenerate them

To keep the repository small, the full ~4 MB evidence file is committed only for a variant whose
signature differs from the committed run. For the others this directory holds the `compare-<variant>.json`
(output of the committed `--compare` against the committed evidence), the `effect-controls-<variant>.json`,
and the sha256 of the evidence file that was measured; the evidence itself can be regenerated with the
command shown (`--keep-evidence all` keeps it; inode numbers, paths and timestamps differ between runs, so
a regenerated file has a different sha256 but should have the same verdict signature).

| Variant | Evidence sha256 (first run) | Evidence file | Regenerate |
| --- | --- | --- | --- |
| `wrapper_control_tmpfs` | `d6ed39d811d77277920945ab1a6decd15773cba90cbc015c06e8c4584d43e6be` | not committed (identical signature) | `python3 research/tools/run_permission_probe_v2_variants.py --run wrapper_control_tmpfs --keep-evidence all --output-dir <directory>` |
| `overlayfs_on_tmpfs` | `ce95b91b97705a3008e1baff5b6568f9511db2dc1334c8800c2256e5e87cb454` | not committed (identical signature) | `python3 research/tools/run_permission_probe_v2_variants.py --run overlayfs_on_tmpfs --keep-evidence all --output-dir <directory>` |
| `overlayfs_on_ext4` | `be95e5cbe9c5cdfee70876bee91bd82e344b14b76e6f735af19631cd80d0f776` | not committed (identical signature) | `python3 research/tools/run_permission_probe_v2_variants.py --run overlayfs_on_ext4 --keep-evidence all --output-dir <directory>` |
| `bind_mount_ext4` | `43f7fb9d35d3d995979227edd69d9f851216808b95eed6be850b12981ae27d36` | not committed (identical signature) | `python3 research/tools/run_permission_probe_v2_variants.py --run bind_mount_ext4 --keep-evidence all --output-dir <directory>` |
| `ext4_scratch_with_fill` | `ce040e5b9e6bb7c8ec10fc0f1a86b610dfc79eb49b100dd5b2c7b4d6a5c0d3dd` | not committed (identical signature) | `python3 research/tools/run_permission_probe_v2_variants.py --run ext4_scratch_with_fill --keep-evidence all --output-dir <directory>` |
| `protected_regular_1` | `9b263654f6378fa39a002c7a986bd993662cbec56f4c5a42575adea052770dec` | not committed (identical signature) | `python3 research/tools/run_permission_probe_v2_variants.py --run protected_regular_1 --keep-evidence all --output-dir <directory>` |
| `protected_regular_2` | `7e1f35e687ec1c607c55c9e505e4bd30ac488e42a99e480191afc2eab33966d0` | not committed (identical signature) | `python3 research/tools/run_permission_probe_v2_variants.py --run protected_regular_2 --keep-evidence all --output-dir <directory>` |
| `protected_hardlinks_0` | `c68cef938ff7ac67b7220e04465fe84ba95ac8b9788b26c95a5970b8b16e8b62` | `evidence-protected_hardlinks_0.json` | `python3 research/tools/run_permission_probe_v2_variants.py --run protected_hardlinks_0 --keep-evidence all --output-dir <directory>` |
| `protected_symlinks_1` | `259a892ae667edfd5c9996d761826b2a8225689f9b837c6c549eb6b5dd85d710` | not committed (identical signature) | `python3 research/tools/run_permission_probe_v2_variants.py --run protected_symlinks_1 --keep-evidence all --output-dir <directory>` |

## Sysctl handling

The three sysctls are global to the machine. The wrapper reads the originals, writes a marker file in the
temp directory while any value is changed, restores in a `finally` block and on SIGTERM/SIGINT, verifies
the values read back and prints them, and refuses to start if a marker from an earlier run exists
(`--restore-stale-marker` recovers). After all runs `cat /proc/sys/fs/protected_regular
/proc/sys/fs/protected_hardlinks /proc/sys/fs/protected_symlinks | tr '\n' ' '` printed `0 1 0`,
no marker file existed, and `mount | grep -iE 'probe|cse227'` was empty.

## Limitations

- One kernel, one VM; not the baseline image. This wrapper has no docker mode, so none of the variants
  was run in the image, and the image's own sysctl values (see the Docker package's README) were not
  combined with these filesystems.
- The overlay mounts had an empty lower layer: every fixture file is created after the mount and lives in
  the upper layer. Files that already exist in a lower (image) layer and are copied up on first write were
  not measured, because the fixture requires an empty probe root.
- A bind mount of ext4 was used as a stand-in for a Docker bind mount or named volume; Docker's own mount
  options, user-namespace remapping, rootless mode, idmapped mounts and LSM policy were not involved.
- Records and workspace on different filesystems were measured only for the fill control (as in probe 02);
  the ordinary operations across a filesystem boundary need a fixture change (see the not-run variant).
- The fill filesystems were small tmpfs in every variant (the fixture accepts nothing else), so disk
  exhaustion on overlayfs or ext4 itself, quotas and reserved blocks were not measured.
- `protected_fifos` was not varied. Each sysctl was varied alone, not in combination.
- The effect controls are a wrapper-level supplement with their own small drop-privilege harness (using the
  fixture's `drop_identity`); they are not probe-02 cells and have no counterpart in the committed evidence.
- Same limits as probe 02: synthetic proxies, agent limited to UID 1000 without capabilities, one account
  for recorder and tools in the current wrapper, in-process editors not modelled.
