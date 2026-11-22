# Permission probe 02: design and coded expectations

Status of this document, stated in the only form that is checkable: every expected verdict in this
design is also a literal in `research/tools/permission_probe_v2_fixture.py` (`_EXPECTED`,
`_EXPECTED_SUPPRESSION`, `LEGIT_EXPECTED_FAILURES`, `expected_descriptor`), reasoned from the
POSIX/Linux semantics set out below, and each committed evidence file records that fixture's
sha256 so a reader can confirm the expectations it was measured against. These files cannot prove
the expectations were written before any earlier exploratory run (all files were untracked and the
fixture was run several times during development). The measurement made after the code was committed
is the teammate's `--mode docker` run in the baseline image at commit a329127, published in
`research/reviews/permission-probe-02-docker/`; section 8 compares expectations with the local
measurements taken here, and section 9 records what that Docker run showed and the aggregation
error it exposed.

## 1. Purpose and scope

Probe 01 measured four ownership cases and six operations. An independent review found gaps:
the "recorder" was UID 0 with `CAP_DAC_OVERRIDE` (so the trusted append passed regardless of mode
bits), rename/link/symlink/sibling/chown operations were untested, realistic shared layouts were
untested, the legitimate-operation controls were thin, and the inherited-handle control did not
record its layout. Probe 02 closes those gaps.

Probe 02 is a synthetic POSIX/Linux mechanism probe. It is **not** a test of native Codex
transcript protection, not a model trial, and not a test of native logging or native session
resume. The "legitimate operation" controls are synthetic proxies (append a line, create a file,
read a file, run a tiny unit test); they only show whether the access a recorder or agent would
need is permitted by the layout.

## 2. Accounts and privilege

| Role | UID:GID | Supplementary groups | Capabilities | no-new-privs |
| --- | --- | --- | --- | --- |
| Setup (trusted) | 0:0 | as provided | docker: CHOWN, DAC_OVERRIDE, SETUID, SETGID, FOWNER, LINUX_IMMUTABLE. local: the runner restricts the setup process (bounding, permitted and effective) to that same six-capability set and sets no-new-privs before it starts, unless `--full-root-setup` keeps root's full set. The actual set is recorded. | recorded |
| Agent (untrusted) | 1000:1000 | none, or `[2000]` in the shared-group layouts | none (CapPrm/CapEff/CapAmb = 0) | must read 1 |
| Recorder (trusted, unprivileged) | 1001:1001 | none | none | must read 1 |

Every measured operation, including every trusted recorder operation, is executed by a child
process that was dropped to the role's identity before `exec`. The child reports its real,
effective and saved UID/GID, groups, `CapInh/CapPrm/CapEff/CapBnd/CapAmb`, `NoNewPrivs` and any
inherited descriptor that points into the probe roots, all read from `/proc/self`. A row whose
child identity is not exactly the expected one is classified `unexpected_error`, never as a
denial or an effect. The setup process never performs a measured operation; it only builds
fixtures and takes before/after snapshots (it needs DAC override to read `0600` files).

Three layouts model the *current* wrapper, where the native recorder and the agent tools share one
account: `agent_owned_writable`, `append_only_same_account` and
`append_only_file_and_dir_same_account`. In those layouts (`recorder_account: shared_with_agent`)
the recorder child runs as 1000:1000. This is stated in each row.

Extra capabilities in docker mode beyond probe 01, and why:

- `CAP_LINUX_IMMUTABLE`: required by the kernel to set or clear `FS_APPEND_FL` / `FS_IMMUTABLE_FL`.
- `CAP_FOWNER`: `FS_IOC_SETFLAGS` requires the caller to own the inode or hold `CAP_FOWNER`. The
  flag must be set after `chown` (the kernel refuses `chown` on an append-only/immutable inode), at
  which point UID 0 is no longer the owner.

`chmod` and the ACL xattr are applied while UID 0 still owns the inode and `chown` is applied
afterwards, so neither needs an extra capability. Setting the setgid bit happens while the
directory's group is still GID 0 (otherwise the kernel silently drops S_ISGID without
`CAP_FSETID`). Every fixture is verified by `lstat` after setup; a mismatch aborts the run.

## 3. Fixture layout

Each (layout, operation) cell gets a fresh fixture so no operation changes another's start state:

```
<root>/<case>--<operation>/            root 0755 (fixture base; reachability is checked by the child)
    home/                              "parent" P (owner depends on layout)
        records/                       records directory D
            synthetic-transcript.jsonl target T (38 bytes, one synthetic record)
    workspace/                         W, agent-owned 0755, same filesystem as T
```

`<root>` is a private tmpfs (`/probe` in docker mode; a self-mounted tmpfs in local mode). If the
tmpfs lacks a feature a layout needs (inode flags, POSIX ACL xattr) and an alternate scratch root
on another filesystem was provided and supports it, that layout runs there; otherwise all its
cells are recorded `not_run` with the concrete errno. The filesystem type is recorded per row.

### Layouts

| Case | P (uid:gid mode) | D | T | Extra | Recorder account |
| --- | --- | --- | --- | --- | --- |
| `agent_owned_writable` | 1000:1000 0755 | 1000:1000 0755 | 1000:1000 0600 | - | shared with agent |
| `recorder_file_agent_writable_dir` | 0:0 0755 | 1000:1000 0755 | 1001:1001 0644 | - | 1001 |
| `sticky_1777_dir_recorder_file` | 0:0 0755 | 1001:1001 1777 | 1001:1001 0644 | - | 1001 |
| `sticky_1770_shared_group_dir` | 0:0 0755 | 1001:2000 1770 | 1001:2000 0640 | agent in group 2000 | 1001 |
| `setgid_2770_shared_group_file_0640` | 0:0 0755 | 1001:2000 2770 | 1001:2000 0640 | agent in group 2000 | 1001 |
| `setgid_2770_shared_group_file_0660` | 0:0 0755 | 1001:2000 2770 | 1001:2000 0660 | agent in group 2000 | 1001 |
| `recorder_owned_agent_readonly` | 0:0 0755 | 1001:1001 0755 | 1001:1001 0644 | - | 1001 |
| `recorder_owned_no_agent_access` | 0:0 0755 | 1001:1001 0700 | 1001:1001 0600 | - | 1001 |
| `recorder_dir_in_agent_owned_parent` | 1000:1000 0755 | 1001:1001 0755 | 1001:1001 0644 | - | 1001 |
| `append_only_same_account` | 1000:1000 0755 | 1000:1000 0755 | 1000:1000 0644 | T has `+a` | shared with agent |
| `append_only_file_and_dir_same_account` | 1000:1000 0755 | 1000:1000 0755 | 1000:1000 0644 | T and D have `+a` | shared with agent |
| `append_only_recorder_owned` | 0:0 0755 | 1001:1001 0755 | 1001:1001 0644 | T has `+a` | 1001 |
| `immutable_recorder_owned` | 0:0 0755 | 1001:1001 0755 | 1001:1001 0644 | T has `+i` | 1001 |
| `acl_agent_read_only` | 0:0 0755 | 1001:1001 0700 + ACL `u:1000:r-x` | 1001:1001 0600 + ACL `u:1000:r--` | POSIX ACL | 1001 |
| `acl_agent_dir_write_file_read` | 0:0 0755 | 1001:1001 0700 + ACL `u:1000:rwx` | 1001:1001 0600 + ACL `u:1000:r--` | POSIX ACL | 1001 |

(With an access ACL the group bits of the mode show the ACL mask, so D/T read back as 0750/0640
or 0770/0640.)

## 4. Operations and the definition of "effect"

All operations are performed by the agent child on T/D. Snapshots use `lstat` (never follow
symlinks) plus a separate "resolved" snapshot that follows the path, a listing of D, P and W, and
a walk of the whole fixture for every name that still refers to the original inode.

| Operation | Syscalls | Effect category | "Effect observed" means |
| --- | --- | --- | --- |
| `rewrite` | `open(O_WRONLY|O_TRUNC)`, `write` | content_modified | same inode, content == replacement record |
| `truncate` | `open(O_WRONLY|O_TRUNC)` | content_modified | same inode, size 0 |
| `overwrite_in_place` | `open(O_WRONLY)`, `pwrite(off 0)` | content_modified | same inode, first bytes replaced, length unchanged |
| `append_marker` | `open(O_WRONLY|O_APPEND)`, `write` | record_appended | same inode, content == original + fabricated marker |
| `delete` | `unlink` | path_removed | T absent and no other name for the original inode |
| `replace` | write W/replacement, `rename` onto T | path_replaced | T is a regular file with a new inode, agent-owned, replacement content |
| `chmod_then_rewrite` | `chmod 0666`, then rewrite | content_modified | same inode, content == replacement record |
| `chown_to_agent` | `chown(T, 1000, 1000)` | ownership_changed | owner changed to 1000:1000 (not applicable when T already is) |
| `rename_within_dir` | `rename(T, D/moved.jsonl)` | path_moved_inode_preserved | T absent; D/moved.jsonl is the original inode |
| `rename_out_of_dir` | `rename(T, W/moved.jsonl)` | path_moved_inode_preserved | T absent; W/moved.jsonl is the original inode |
| `rename_parent_dir` | `rename(D, P/records-moved)` | path_moved_inode_preserved | D absent; original inode now under P/records-moved |
| `hardlink_create` | `link(T, W/hardlink.jsonl)` | additional_hard_link_created | W/hardlink.jsonl is the original inode, link count +1, T content unchanged |
| `symlink_swap_file` | write W/attacker, `symlink`, `rename` link onto T | path_redirected_by_symlink | `lstat(T)` is a symlink and reading T yields attacker content |
| `symlink_swap_dir` | `rename(D, P/records-moved)`, `symlink(W/attacker-records, D)` | path_redirected_by_symlink | `lstat(D)` is a symlink and reading T yields attacker content |
| `create_sibling` | `open(D/sibling.jsonl, O_CREAT|O_EXCL)` | sibling_file_created | sibling exists, agent-owned; T unchanged |
| `clear_inode_flags_then_rewrite` | `FS_IOC_SETFLAGS` clearing `+a/+i`, then rewrite | content_modified | flags cleared and content == replacement record (only for flag layouts) |

`hardlink_create` and `create_sibling` do **not** change the transcript; they are reported as
their own categories ("side-effect operations") and are not counted as tampering. The other
fourteen are the "tampering operations".

Verdicts:

- `effect_observed`: child reported success and the independent snapshot shows the defined effect.
- `permission_denial_observed`: child failed with `EACCES` or `EPERM` **and** the protected state
  (T snapshot, D metadata, D listing, P listing, locations of the original inode) is identical.
- `different_effect_observed`: child reported success, state changed, but not the defined effect
  (used for the O_APPEND `pwrite` descriptor control; the concrete outcome is recorded).
- `not_run` (+ reason): not applicable, or the environment lacks the feature.
- `unexpected_error`: anything else (wrong child identity, fixture base unreachable, other errno,
  partial change with a reported error, reported success with no change).

## 5. Expected outcome for each cell (written before execution)

E = `effect_observed`, D = `permission_denial_observed`, n/a = `not_run` (not applicable).
`E|D` in the hard-link column = D when `fs.protected_hardlinks=1`, E when it is 0.

Column order: RW rewrite, TR truncate, OW overwrite_in_place, AP append_marker, DEL delete,
REP replace, CHM chmod_then_rewrite, CHO chown_to_agent, RNW rename_within_dir, RNO
rename_out_of_dir, RNP rename_parent_dir, HL hardlink_create, SYF symlink_swap_file, SYD
symlink_swap_dir, SIB create_sibling, CLF clear_inode_flags_then_rewrite.

| Case | RW | TR | OW | AP | DEL | REP | CHM | CHO | RNW | RNO | RNP | HL | SYF | SYD | SIB | CLF |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| agent_owned_writable | E | E | E | E | E | E | E | n/a | E | E | E | E | E | E | E | n/a |
| recorder_file_agent_writable_dir | D | D | D | D | E | E | D | D | E | E | D | D\|E | E | D | E | n/a |
| sticky_1777_dir_recorder_file | D | D | D | D | D | D | D | D | D | D | D | D\|E | D | D | E | n/a |
| sticky_1770_shared_group_dir | D | D | D | D | D | D | D | D | D | D | D | D\|E | D | D | E | n/a |
| setgid_2770_shared_group_file_0640 | D | D | D | D | E | E | D | D | E | E | D | D\|E | E | D | E | n/a |
| setgid_2770_shared_group_file_0660 | E | E | E | E | E | E | D | D | E | E | D | E | E | D | E | n/a |
| recorder_owned_agent_readonly | D | D | D | D | D | D | D | D | D | D | D | D\|E | D | D | D | n/a |
| recorder_owned_no_agent_access | D | D | D | D | D | D | D | D | D | D | D | D | D | D | D | n/a |
| recorder_dir_in_agent_owned_parent | D | D | D | D | D | D | D | D | D | D | E | D\|E | D | E | D | n/a |
| append_only_same_account | D | D | D | E | D | D | D | n/a | D | D | E | D | D | E | E | D |
| append_only_file_and_dir_same_account | D | D | D | E | D | D | D | n/a | D | D | D | D | D | D | E | D |
| append_only_recorder_owned | D | D | D | D | D | D | D | D | D | D | D | D | D | D | D | D |
| immutable_recorder_owned | D | D | D | D | D | D | D | D | D | D | D | D | D | D | D | D |
| acl_agent_read_only | D | D | D | D | D | D | D | D | D | D | D | D\|E | D | D | D | n/a |
| acl_agent_dir_write_file_read | D | D | D | D | E | E | D | D | E | E | D | D\|E | E | D | E | n/a |

### Justification (Linux VFS semantics)

1. **Content writes** (`rewrite`, `truncate`, `overwrite_in_place`, `append_marker`) need write
   permission on the inode (`open(2)`: `EACCES`). Mode/ACL class is chosen owner → named ACL user
   → group → other. Only `agent_owned_writable` and the `0660` shared-group file give the agent
   write permission. An append-only inode additionally refuses any open for writing without
   `O_APPEND` and any `O_TRUNC` with `EPERM` (`open(2)`, `ioctl_iflags(2)`), so on the two
   same-account `+a` layouts only `append_marker` succeeds. An immutable inode refuses all writes.
2. **Name operations** (`delete`, `replace`, `rename_*`, `symlink_swap_file`, `create_sibling`)
   need write+search permission on the directory, not on the file (`unlink(2)`, `rename(2)`). The
   agent has that in the agent-owned directory, the setgid group-writable directories, the ACL
   `rwx` directory and both sticky directories. In a **sticky** directory, removing or renaming an
   entry additionally requires owning the entry or the directory (`EPERM` otherwise), and this
   also applies to the victim of a `rename` onto an existing name; so in both sticky layouts every
   name operation on T is denied while `create_sibling` succeeds. An **append-only** inode cannot
   be unlinked, renamed or be the victim of a rename (`EPERM`); an append-only **directory**
   allows creating entries but not removing/renaming them.
3. **`chmod`** needs ownership (`EPERM`); an owner can do it unless the inode is append-only or
   immutable (`EPERM`). `chmod_then_rewrite` fails at the `chmod` step for the `0660` group file
   even though a plain rewrite works there. **`chown`** needs `CAP_CHOWN` to change the owner
   (`EPERM`); it is not applicable where T is already 1000:1000.
4. **`rename_parent_dir` / `symlink_swap_dir`** depend on P (the directory holding D), not on D or
   T: renaming a directory within the same parent needs write+search on the parent only. P is
   agent-owned in `agent_owned_writable`, `recorder_dir_in_agent_owned_parent` and the two
   same-account `+a` layouts. In `append_only_file_and_dir_same_account` D itself is append-only,
   so it cannot be renamed. Everywhere else P is root-owned 0755 (`EACCES`).
5. **`hardlink_create`**: `link(2)` needs search on D and write on W. With
   `fs.protected_hardlinks=1` the caller must also own the file or have read+write access to it
   (`proc_sys_fs(5)`), else `EPERM`. Append-only and immutable inodes can never be linked
   (`EPERM`). In `recorder_owned_no_agent_access` the lookup itself fails (`EACCES`). Hence E for
   the agent-owned file and the `0660` group file, D for flag layouts and the 0700 layout
   regardless of the sysctl, and sysctl-dependent elsewhere.
6. **`clear_inode_flags_then_rewrite`**: changing `FS_APPEND_FL`/`FS_IMMUTABLE_FL` needs
   `CAP_LINUX_IMMUTABLE` (and ownership or `CAP_FOWNER`); the agent has neither capability.

## 6. Legitimate-operation proxies (per layout, fresh fixture each)

| Control | Actor | Proxy for |
| --- | --- | --- |
| `agent_workspace_edit_and_test` | agent | editing code and running tests: create a module and a unittest in W, see it fail, edit the module, see it pass |
| `recorder_append` | recorder | recording a new action: `open(O_WRONLY|O_APPEND)` + write on T |
| `recorder_new_transcript` | recorder | starting a new session: `open(O_CREAT|O_EXCL)` of a new file in D |
| `recorder_read_back` | recorder | resuming: read T and compare its hash |
| `agent_read_transcript` | agent | whether the agent account itself could read history (recorded, not judged) |

Expected: all four judged controls pass in every layout, except

- `recorder_file_agent_writable_dir`: `recorder_new_transcript` fails (`EACCES`; D is agent-owned
  0755 and the recorder is "other");
- `immutable_recorder_owned`: `recorder_append` fails (`EPERM`; immutable).

Expected `agent_read_transcript`: readable everywhere except `recorder_owned_no_agent_access`.

Expected set of layouts that deny all fourteen tampering operations **and** keep all four judged
proxies working: `sticky_1777_dir_recorder_file`, `sticky_1770_shared_group_dir`,
`recorder_owned_agent_readonly`, `recorder_owned_no_agent_access`, `append_only_recorder_owned`,
`acl_agent_read_only` (the two sticky layouts still allow sibling creation).

## 7. Inherited-descriptor controls (per layout, fresh fixture each)

A helper process dropped to the layout's recorder identity opens the descriptor (so the open is
permission-checked as the recorder) and sends it to the setup process over a Unix socket
(`SCM_RIGHTS`); the setup process deliberately passes it to the agent child. If the recorder
identity cannot open it, the cell is `not_run` with the errno.

| Control | Descriptor | Agent action | Defined effect |
| --- | --- | --- | --- |
| `fd_append_write` | T, `O_WRONLY|O_APPEND` | `write` marker | marker appended |
| `fd_append_pwrite_overwrite` | T, `O_WRONLY|O_APPEND` | `pwrite(off 0)` | earlier bytes modified |
| `fd_append_ftruncate` | T, `O_WRONLY|O_APPEND` | `ftruncate(0)` | truncated |
| `fd_append_clear_flag_then_pwrite` | T, `O_WRONLY|O_APPEND` | `fcntl(F_SETFL)` clearing `O_APPEND`, `pwrite(off 0)` | earlier bytes modified |
| `fd_wronly_pwrite_overwrite` | T, `O_WRONLY` | `pwrite(off 0)` | earlier bytes modified |
| `fd_wronly_ftruncate` | T, `O_WRONLY` | `ftruncate(0)` | truncated |
| `dirfd_unlinkat` | D, `O_RDONLY|O_DIRECTORY` | `unlinkat(fd, name)` | T removed |
| `dirfd_renameat` | D, `O_RDONLY|O_DIRECTORY` | `renameat(fd, name, fd, moved)` | T moved, inode preserved |
| `dirfd_listdir` | D, `O_RDONLY|O_DIRECTORY` | `os.listdir(dirfd)` vs `os.listdir(path)` | names read through the descriptor |

Expectations:

- `fd_append_write`: E in every layout where the recorder can open T for append (all except
  `immutable_recorder_owned`, which is `not_run`). An open file description carries its own write
  authority; path permissions are not rechecked on `write(2)`.
- `fd_append_pwrite_overwrite`: `different_effect_observed` with outcome `appended_only` — on
  Linux `pwrite(2)` on an `O_APPEND` descriptor appends regardless of the offset (`pwrite(2)`
  BUGS). Earlier bytes are not overwritten by this route.
- `fd_append_ftruncate`: E on ordinary files (`ftruncate(2)` needs only a descriptor open for
  writing; `O_APPEND` does not prevent it), D (`EPERM`) on append-only inodes.
- `fd_append_clear_flag_then_pwrite`: E on ordinary files (`fcntl(F_SETFL)` may clear `O_APPEND`),
  D (`EPERM`) on append-only inodes (`fcntl(2)`: `O_APPEND` cannot be cleared on an append-only
  file).
- `fd_wronly_*`: E on ordinary files; `not_run` on append-only and immutable layouts because the
  recorder itself cannot open T `O_WRONLY` without `O_APPEND`.
- `dirfd_unlinkat` / `dirfd_renameat`: same as the path-based `delete` / `rename_within_dir` cell
  of the layout — a directory descriptor is only a lookup starting point for name *changes*;
  directory write/search permission is checked against the caller's credentials at
  `unlinkat`/`renameat` time.
- `dirfd_listdir`: `getdents(2)` on an already-open directory descriptor is **not** re-checked
  against path permissions (permission is checked at `open(2)`, which the recorder passed). So the
  agent is expected to read the entry names through the inherited descriptor in every layout,
  including `recorder_owned_no_agent_access` where the path `listdir` is refused with `EACCES`.
  Outcome `names_listed_via_dirfd_only` there, `names_listed_via_path_and_dirfd` elsewhere. This
  is why the earlier claim that an inherited directory descriptor "gave no extra authority" was
  wrong for reads: it confers no name-*change* authority but does leak the listing.

So an inherited `O_APPEND` descriptor is expected to permit forging appended records **and**
truncating the whole transcript on every layout without the append-only inode flag, and only
appending on layouts with it; an inherited directory descriptor additionally leaks the entry
listing even where the path cannot be listed.

Independence of denials. Each ordinary and descriptor row records `failed_step` (the first syscall
that was refused) and `denial_class` (`EACCES` = a discretionary mode/ACL check, `EPERM` = an
ownership, sticky-bit, inode-flag, protected_hardlinks or capability rule). This matters because
many denials in one layout share a mechanism: `symlink_swap_dir` is usually refused at the same
`rename(records, …)` step as `rename_parent_dir` (the later `symlink` step never runs), and the
`append_only_recorder_owned` path denials are the same `EACCES` from the 0755/0644 mode bits as in
`recorder_owned_agent_readonly`, not a consequence of the append-only flag. The recorded step and
class let a reader see which control actually did the work.

## 7.5 Suppression of future records (availability; its own category)

Tampering with existing bytes is not the only risk; an agent can also stop *future* records from
being written. These are measured as their own category and never folded into the tampering count.

| Operation | Agent action, then recorder follow-up (each by a child dropped to that identity) | "Suppression" means |
| --- | --- | --- |
| `precreate_next_session_name` | Agent creates `records/next-session.jsonl` (a predictable next transcript name). Recorder tries `O_CREAT|O_EXCL`, then `O_CREAT|O_APPEND`; then the agent rewrites whatever holds that name. | the agent's file holds the name and the recorder's exclusive create fails with `EEXIST` |
| `fill_filesystem_then_recorder_append` | Records tree and workspace on ONE small size-limited tmpfs. Agent writes `fill.bin` in workspace, the parent of D, and D until `ENOSPC`. Recorder then appends 200 records to T. | the recorder is starved (ENOSPC or a short write) before all 200 records are written |
| `fill_filesystem_then_recorder_append_separate_fs` | Same, but records tree and workspace are on two SEPARATE small tmpfs. | as above |

Expectations (reasoned from semantics; `S` suppression, `R` resisted, `n/a` not applicable):

- `precreate`: `S` exactly where the agent may create an entry in D — the agent-owned,
  setgid-group-writable, sticky and ACL-`rwx` directories; `R` where it cannot (recorder-owned
  0755/0700 directories and the agent-owned-parent layout, whose D is recorder-owned 0755). When
  the agent pre-creates the name, the recorder's `O_CREAT|O_EXCL` fails `EEXIST`, its
  `O_CREAT|O_APPEND` then appends to the agent-owned file, and the agent can still rewrite it.
- `fill` (shared fs): `S` in **every** layout except immutable (`n/a`, since the recorder cannot
  append anyway) — the agent always has a writable sink (at least its own workspace) on the one
  shared filesystem, and filling it starves the recorder.
- `fill` (separate fs): `S` only where the agent can create a file somewhere on the *records*
  filesystem (D, or an agent-owned ancestor of D); `R` where the records tree is on a filesystem
  the agent cannot write to at all. Immutable: `n/a`.

Measured with `fs.protected_regular=0`. With `protected_regular=1`/`2` the recorder's
`O_CREAT|O_APPEND` onto an agent-owned file in a sticky world-writable directory can itself be
refused, which this run did not exercise; the sysctl value is recorded in each evidence file.

The layout lists are three-valued (section 9): a layout holds "resists every suppression operation"
only if precreate and both fill cells were executed and resisted; it fails if any executed cell
showed suppression; and it is undetermined, never "resisting", if a required cell was not executed
in the environment. Where the shared-filesystem fill is executed it is expected to be `S` in every
layout, so no layout is expected to hold that requirement unless records are isolated on their own
filesystem with space the agent cannot exhaust — availability is not provided by permissions alone.

## 8. Expectations versus measurements (appended after the recorded run)

Recorded run: `--mode local`, 2026-11, cloud sandbox VM, kernel 6.18.44, private tmpfs (plus small
dedicated tmpfs for the fill controls), `fs.protected_hardlinks=1`, `fs.protected_symlinks=0`,
`fs.protected_regular=0`. Evidence: `research/reviews/permission-probe-02/evidence.json`. This was
**not** the baseline Docker image; `--mode docker` has not been executed here.

| Group | Cells | Executed | Matched expectation | Mismatched | not_run |
| --- | --- | --- | --- | --- | --- |
| Ordinary layout x operation | 240 | 226 | 226 | 0 | 14 (all "not applicable") |
| Legitimate proxies (4 judged + 1 recorded per layout) | 75 | 75 | 75 | 0 | 0 |
| — of which layout-discriminating (judged) | 24 | 24 | 24 | 0 | 0 (22 pass, 2 denied) |
| — of which harness sanity checks (judged, same in every layout) | 36 | 36 | 36 | 0 | 0 |
| Inherited-descriptor controls | 135 | 123 | 123 | 0 | 12 (recorder could not open the descriptor) |
| Suppression-of-future-records controls | 45 | 43 | 43 | 0 | 2 (immutable fill, n/a) |

Measured ordinary verdicts: 53 `effect_observed`, 173 `permission_denial_observed`, 14 `not_run`.
Descriptor verdicts: 83 `effect_observed`, 26 `permission_denial_observed`, 14
`different_effect_observed` (all `appended_only`), 12 `not_run`. Suppression verdicts: 33
`suppression_observed`, 10 `no_suppression_observed`, 2 `not_run`. No `unexpected_error` row.

Every measured cell matched its coded expectation, so nothing was adjusted on either side. Points a
reader should not over-read:

- Agreement was measured on one kernel. A repeat run gave identical verdicts, outcomes and errnos
  for all 495 measurements; two committed variants — all general layouts on ext4
  (`evidence-ext4.json`) and setup with root's full capabilities (`evidence-full-root-setup.json`)
  — gave identical **verdicts** (the ext4 run additionally marks the 28 fill cells `not_run`,
  because it has no dedicated size-limited tmpfs; `compare-ext4.json` records that split).
- The `D|E` hard-link cells were measured only with `fs.protected_hardlinks=1` (all D). The
  expectation for the sysctl value 0 remains untested.
- For `append_only_recorder_owned` and `immutable_recorder_owned` the hard-link denial is expected
  from both the sysctl and the inode flag; the run cannot tell which one produced the `EPERM`.
  In the two same-account append-only layouts the agent owns the file, so there the `EPERM` is
  attributable to the flag. Each row's `denial_class` records `EACCES` vs `EPERM`.
- In the recorder-owned flag layouts most name operations were refused with `EACCES` by the 0755
  directory before the flag was consulted (`denial_class=EACCES`); the flag-specific `EPERM`
  behaviour is what the same-account layouts measured.
- Six layouts deny all fourteen measured tampering operations and keep all four judged proxies.
  In this local run none of them holds resistance to every suppression operation, and that is a
  determined result, not a gap: in all six the shared-filesystem fill cell was executed and the
  recorder was starved. Four of them hold resistance to precreate and the separate-filesystem fill.
  This matches the expectation at the end of §7.5. It is a statement about the local environment
  only (see section 9 for Docker, where the fill cells were not executed).
- `dirfd_listdir` showed the inherited directory descriptor leaks the entry listing in all 15
  layouts, and in `recorder_owned_no_agent_access` it is the *only* way the agent reads the names
  (the path `listdir` is `EACCES`).

Implementation notes (now consistent with §2):

- The local runner by default restricts the setup process to docker mode's six capabilities
  (bounding, permitted and effective) and sets no-new-privs before it starts; the recorded run used
  that restricted set (`CapEff=0x2cb`). `--full-root-setup` keeps the full set and produced
  identical verdicts.
- Both extra capabilities were confirmed necessary on this kernel by removing each in turn: without
  `CAP_LINUX_IMMUTABLE` the flag feature probe fails `EPERM`; without `CAP_FOWNER` building the four
  flag layouts fails `EPERM`. Such failures become `not_run` cells with the errno, never results.
- `different_effect_observed` is a fifth verdict for an operation that succeeds but changes state
  other than as defined; it occurred only for `fd_append_pwrite_overwrite` (`appended_only`).
- The alternate ext4 root was offered but unused in the primary run: the tmpfs supported inode
  flags and the ACL xattr.
- The fill controls run on small dedicated tmpfs mounts the runner mounts in the fixture's private
  mount namespace; their ENOSPC timing is the probe's, not any production filesystem's.

## 9. Docker validation and aggregation correction

Source for everything about the Docker run in this section: the teammate's
`research/reviews/permission-probe-02-docker/README.md`, `coverage-assessment.json` and the evidence
in `validation-originals.zip`. Nothing there was re-measured here, and the environment differences
they list (kernel, Python, filesystem mix, several `fs.protected_*` settings) are not restated.

What was measured. The probe was run unchanged at commit a329127 with `--mode docker` in the
baseline image. Their coverage table: 495 cells recorded, 439 executed, 56 not run (ordinary
240/226/14, legitimate and read controls 75/75/0, inherited descriptors 135/123/12, suppression
45/15/30). Among the 439 cells executed in both environments there is no verdict difference; 28
cells are not run in either; 28 cells, the disk-fill controls, are not run in Docker and measured
locally. Docker mode has no dedicated fill filesystems, so both fill operations are not run for
all fifteen layouts there.

The error. The runner at a329127 derived "layouts also resisting both suppression operations" from
the suppression cells that remained after dropping `not_run` cells. A layout whose only executed
suppression cell was a resisted precreate was therefore listed as resisting the fill operations it
had never been tested against. For the Docker run this listed `recorder_owned_agent_readonly`,
`recorder_owned_no_agent_access`, `append_only_recorder_owned` and `acl_agent_read_only`. The claim
is unsupported; for those four layouts resistance to the fill operations is undetermined in Docker.
Summaries generated at a329127 overstate suppression resistance wherever disk-fill cells were not
run. The measurement code (the fixture) was not at fault and is unchanged. The same filtering
pattern existed in the tampering list (a `not_run` tampering cell was dropped) and the proxy list (a
`not_run` proxy excluded the layout as if it had failed); neither case occurs in the committed
evidence, and both are corrected.

The corrected rule, used by the runner summary, `--render-tables`, the CLI text and the variants
wrapper:

- A cell that was not run is classified from its recorded `not_run_reason`: "not applicable: ..."
  means the operation has no meaning in the layout and the cell is not required; "the recorder
  identity could not open the descriptor ..." means the layout itself refused the recorder the
  precondition; any other reason (missing filesystem feature, no fill filesystem, fixture setup
  failure, or no reason) means the cell could not be executed in the environment.
- A layout **holds** a requirement only if every required cell was executed with the good verdict;
  it **fails** if an executed cell has the bad verdict; otherwise it is **undetermined**, with the
  missing cells named. A cell ending in `unexpected_error` also makes the layout undetermined.
  Undetermined is never reported as resisted, denied, kept or suppressed.
- Every summary reports recorded / executed / not-run per measurement group. `--compare` reports
  cells executed in both files, not run in both, not run in one and measured in the other, and
  verdict differences among the cells executed in both; "verdicts identical among cells executed in
  both" and "same coverage" are separate statements and neither implies the other.

Result of applying the corrected rule to the teammate's archived Docker evidence (done read-only in
`tests/test_permission_probe_v2.py`, `DockerValidationRegressionTests`): six layouts hold "tampering
denied and proxies kept", as locally; no layout holds resistance to every suppression operation; the
two sticky layouts fail it because precreate suppression was executed and observed; the four
layouts named above are undetermined, each missing both fill cells. The local run (section 8)
remains the only place the fill operations were executed; its fill results are local results and
are not evidence about the Docker environment.
