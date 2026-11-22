# Permission probe 02 in Docker with the disk-fill controls executable

Status: **the Docker run itself has NOT been executed.** This machine has no Docker daemon. What exists is
a runner whose docker command and mount validation are unit tested with mocks, and a real local run that
exercises the same fixture invocation with pre-mounted filesystems. Independent review: pending.

## Why

In the teammate's baseline-image run (`../permission-probe-02-docker/README.md`) both disk-fill operations
were not run for all 15 layouts: 28 cells that could not be executed, because the unprivileged container
cannot mount the small dedicated fill filesystems and the committed docker mode supplies none. For those
cells resistance is undetermined in the image. The committed fixture already accepts
`--fill-records-root` and `--fill-workspace-root`.

`research/tools/run_permission_probe_v2_docker_fill.py` changes no measurement code. It imports the
committed runner and fixture and adds two size-limited tmpfs mounts that the container **runtime** provides
(`docker create --tmpfs`), then passes their paths to the fixture. Everything else is the committed docker
mode: same image pin, `--pull=never`, `--network none`, `--read-only`, `--cap-drop ALL` with the same six
documented capabilities, `no-new-privileges`, the same pids/memory/cpu limits, no host bind, labelled
cleanup. From `docker inspect` it requires exactly the three tmpfs mounts below with exactly these
options, the expected fixture arguments, and no bind mount, before the container is started. It refuses to
overwrite existing evidence and prints coverage with the not-run kinds.

Fill mounts: `/probe-fill-records` and `/probe-fill-workspace`, options `rw,nosuid,nodev,noexec,size=4m,mode=0755`, which
are the committed local mode's fill options, so the ENOSPC point is comparable with the committed local
evidence.

| Option | Why |
| --- | --- |
| `rw` | the fixture must create files there |
| `nosuid` | no set-user-ID program can gain privilege from the probe filesystems |
| `nodev` | no device nodes |
| `noexec` | nothing on the probe filesystems is executed (the workspace test is read by the interpreter) |
| `size=4m` | small fixed size so the agent's fill reaches ENOSPC quickly and cannot exhaust host memory; the fixture refuses a fill root larger than 8 MiB |
| `mode=0755` | root-owned mount root that the agent and recorder can traverse but not write |

## What a teammate must run in the baseline image (`sha256:eddc3b19…`)

From the repository root, on a machine with the image present locally:

```
python3 research/tools/run_permission_probe_v2_docker_fill.py --mode docker --evidence <new file> --summary <new file>
python3 research/tools/run_permission_probe_v2.py --compare research/reviews/permission-probe-02/evidence.json <new file>
```

The container it creates:

```
docker create --pull=never --name <name> --label org.cse227.permission-probe-v2=<id> --interactive --network none --read-only --user 0:0 --cap-drop ALL --cap-add CHOWN --cap-add DAC_OVERRIDE --cap-add SETUID --cap-add SETGID --cap-add LINUX_IMMUTABLE --cap-add FOWNER --security-opt no-new-privileges --pids-limit 64 --memory 256m --cpus 1 --tmpfs /probe:rw,nosuid,nodev,noexec,size=64m,mode=0755 --tmpfs /probe-fill-records:rw,nosuid,nodev,noexec,size=4m,mode=0755 --tmpfs /probe-fill-workspace:rw,nosuid,nodev,noexec,size=4m,mode=0755 --workdir /probe --entrypoint python3 sha256:eddc3b1939fb346372fe8e6aa2806f1bb03696867704f3e70143e12492115aa5 -I - --fill-records-root /probe-fill-records --fill-workspace-root /probe-fill-workspace
```

What it adds: the 28 disk-fill cells that are unmeasured in the image (14 layouts x 2 fill operations; the
immutable layout's two are not applicable). If it runs as intended, coverage becomes 495 recorded / 467
executed / 28 not run with none in the "could not be executed" kind, and the three-valued lists stop
being undetermined for the fill operations. Whether the verdicts then equal the local ones is exactly what
that run would measure; nothing here predicts it beyond the fixture's coded expectations. Things that can
differ there: the image's kernel and `fs.protected_*` values (see the Docker package's README), tmpfs
accounting under the container memory limit (72 MiB of tmpfs against 256 MiB), and Docker's handling of
the tmpfs options.

## What was executed here: `--mode local-premounted`

To show that the fixture-side path works when someone else provides the mounts, the runner mounted the
filesystems first, in a private mount namespace, and then started the committed fixture with the committed
capability restriction (CHOWN, DAC_OVERRIDE, FOWNER, LINUX_IMMUTABLE, SETGID, SETUID; no CAP_SYS_ADMIN,
no-new-privs) and the fill-root arguments. The fixture process performed no mount. (The helper reused
from the variants wrapper also mounts a fourth small tmpfs that is not passed to the fixture.)

```
python3 research/tools/run_permission_probe_v2_docker_fill.py --mode local-premounted --evidence /tmp/pa/e1.json --summary /tmp/pa/s1.json
python3 research/tools/run_permission_probe_v2.py --compare research/reviews/permission-probe-02/evidence.json /tmp/pa/e1.json
```

- Coverage of the run: 495 recorded, 467 executed, 28 not run
  (16 not applicable to the layout, 12 recorder precondition refused by the layout, 0 could not be
  executed). Disk-fill cells: 30 recorded, 28 executed, 2 not applicable. Expectation mismatches:
  0.
- Compared with the committed probe-02 evidence (`compare-local-premounted.json`): 467
  executed in both, 28 not run in both, 0 not run versus measured,
  0 verdict differences among cells executed in both, same coverage:
  True.
- A second run compared with the first: 467 executed in both, 0
  verdict differences, same coverage: True.
- The evidence is not committed because its signature equals the committed probe-02 evidence on every
  cell. Its sha256 was `3a38842fd15343ce1b1948233b99fa439e10e87b8920aec019b0bbb52a208e40`; `local-premounted-record.json` holds the environment, the
  mounts the runner made, the coverage and the commands. A regenerated file will have another sha256
  (inode numbers, paths, times) and should have the same signature.

This is a local result. It is not a Docker result and does not change what is undetermined in the image.

## Limitations

- The docker mode is mock-tested only: argv construction, inspection validation, refusal on unexpected
  mounts or capabilities, and cleanup. Real Docker behaviour (option parsing, `Mounts` reporting, memory
  accounting) is unverified.
- Local-premounted ran on this sandbox's kernel with its sysctls, not the image's.
- Synthetic proxies, as in probe 02.
