"""Build helper for the derived account-separation image.

Cannot build in the research sandbox (no Docker daemon). Run on a host with Docker.
It builds the derived image FROM the pinned baseline, then records the resulting
image id and the exact set of changes relative to the baseline (new users/group,
replaced shells, added package files), writing a manifest for the operator.

Usage (on a Docker host, from the repository root):

    python3 research/native/account_separation/build_derived_image.py \
        --base <baseline-image-id-or-tag> \
        --tag trace-lab-account-separation:derived \
        --manifest runs/native/account-separation/derived-image-manifest.json
"""

import argparse
import json
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
DOCKERFILE = Path(__file__).resolve().parent / "Dockerfile.account-separation"

# The baseline image the frozen native experiments pin (from
# research/analysis/native-history-comparison-review.md and trace_lab.cli DEFAULT_IMAGE).
PINNED_BASELINE_DIGEST = (
    "sha256:eddc3b1939fb346372fe8e6aa2806f1bb03696867704f3e70143e12492115aa5")

# The exact, intended changes relative to the baseline (for operator verification).
EXPECTED_CHANGES = {
    "new_accounts": ["tool (uid 1002, gid 1002, home /home/tool)"],
    "new_groups": ["shared (gid 2000)"],
    "group_memberships_added": ["tool:shared", "agent:shared"],
    "shells_replaced": {"/bin/bash": "agent-shell stub (real at /bin/bash.real)",
                        "/bin/sh": "agent-shell stub (real at /bin/sh.real)"},
    "codex": "/usr/local/bin/codex is codex_shim.py; the real CLI is /usr/local/bin/codex.real",
    "files_added": ["/opt/trace-lab/research/native/account_separation/*",
                    "/usr/local/libexec-agent-shell-bash", "/usr/local/libexec-agent-shell-sh",
                    "/home/tool (owned by tool)"],
    "unchanged": "default user, working directory, command, Codex binary, every other tool",
    "build_only_packages_removed": ["gcc", "libc6-dev"],
    "known_residue": "/usr/bin/dash and other interpreters stay directly executable; only a process "
                     "started THROUGH /bin/bash or /bin/sh is forced to the agent account",
}


def _docker(*args, check=True):
    proc = subprocess.run(["docker", *args], capture_output=True, text=True)
    if check and proc.returncode:
        raise RuntimeError("docker %s failed: %s" % (args[0], proc.stderr.strip()))
    return proc


def build(base, tag):
    _docker("build", "-f", str(DOCKERFILE), "--build-arg", "BASE_IMAGE=%s" % base,
            "-t", tag, str(ROOT))
    image_id = _docker("image", "inspect", "--format", "{{.Id}}", tag).stdout.strip()
    base_id = _docker("image", "inspect", "--format", "{{.Id}}", base).stdout.strip()
    # The diff relative to the baseline, from image history layers.
    history = _docker("history", "--no-trunc", "--format", "{{.CreatedBy}}", tag).stdout
    return {"base_image": base, "base_image_id": base_id, "derived_image_id": image_id,
            "tag": tag, "expected_changes": EXPECTED_CHANGES,
            "pinned_baseline_digest": PINNED_BASELINE_DIGEST,
            "baseline_digest_matches": base_id.endswith(PINNED_BASELINE_DIGEST.split(":", 1)[1])
                                       or PINNED_BASELINE_DIGEST in base,
            "added_layer_commands": [line for line in history.splitlines() if line.strip()][:12],
            "verify_hint": "Diff the two images with 'container-diff' or export both rootfs and "
                           "compare; the only changes must be those in expected_changes."}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--base", required=True, help="Baseline image id or tag.")
    parser.add_argument("--tag", default="trace-lab-account-separation:derived")
    parser.add_argument("--manifest", type=Path)
    args = parser.parse_args(argv)

    import shutil
    if not shutil.which("docker"):
        print("NOT EXECUTED: no Docker CLI/daemon available. Run this on a Docker host.",
              file=sys.stderr)
        return 2
    manifest = build(args.base, args.tag)
    text = json.dumps(manifest, indent=2)
    if args.manifest:
        args.manifest.parent.mkdir(parents=True, exist_ok=True)
        args.manifest.write_text(text + "\n")
    print(text)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
