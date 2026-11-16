"""Assemble or check the initial-replication handoff without running experiments."""

import argparse
from collections import Counter
import hashlib
import json
from pathlib import Path
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))
from research.tools import finalize_baseline_review as baseline
from research.tools import build_pilot_review as pilot
from research.tools import run_permission_probe as permissions
from research.tools.export_baseline_review import read, require, sha, source_hashes

MANIFEST = Path("research/handoffs/week1-manifest.json")
EVIDENCE = Path("research/reviews/permission-probe-01/evidence.json")
EVIDENCE_SHA = "76b7291199dc3f95a7b69129d38d7f76fe7da394f577ad6695d1fb2a336e5faf"
MUTABLE_CHECKPOINT_FILES = {
    "research/checkpoints/independent-trial.md",
    "research/results/pilot-financial-full-01-summary.json",
}
CASES = {
    "agent_owned_writable": (1000, "0o600", 1000,
        {"rewrite", "truncate", "delete", "replace", "append_marker", "chmod_then_rewrite"}),
    "agent_owned_readonly": (1000, "0o444", 1000, {"delete", "replace", "chmod_then_rewrite"}),
    "protected_file_writable_directory": (0, "0o644", 1000, {"delete", "replace"}),
    "protected_file_and_directory": (0, "0o644", 0, set()),
}
OPERATIONS = {"rewrite", "truncate", "delete", "replace", "append_marker", "chmod_then_rewrite"}
BASE = b'{"event":"original-synthetic-record"}\n'
EDIT = b'{"event":"changed-synthetic-record"}\n'
APPEND = b'{"event":"fabricated-test-marker"}\n'
TRUSTED = b'{"event":"trusted-test-marker"}\n'


def identity(child, inherited=False):
    item = child["identity"]
    require(item["uid"] == [1000] * 3 and item["gid"] == [1000] * 3
            and item["groups"] == [], "Unexpected untrusted process identity.")
    require(item["status"]["NoNewPrivs"] == "1" and all(
        int(item["status"][key], 16) == 0 for key in ("CapEff", "CapPrm", "CapAmb")),
        "Untrusted process retained privileges.")
    handles = item["inherited_probe_fds"]
    require(len(handles) == (1 if inherited else 0), "Unexpected inherited probe handle.")
    if inherited:
        require(type(handles[0]["fd"]) is int and handles[0]["fd"] >= 3
                and handles[0]["target"] ==
                "/probe/inherited-descriptor-control/records/synthetic-transcript.jsonl",
                "The inherited handle targets an unexpected file.")


def contents(snapshot, payload):
    require(snapshot.get("exists") is True
            and snapshot.get("size") == len(payload)
            and snapshot.get("sha256") == hashlib.sha256(payload).hexdigest(),
            "File snapshot does not match the expected measured contents.")


def review_permission(packet):
    run, data, summary = packet["run"], packet["observations"], packet["summary"]
    require(run["status"] == "finished" and run.get("error") is None
            and run["cleanup_verified"] is True and run["model_calls"] == 0,
            "Permission collection or cleanup was incomplete.")
    settings = packet["container_settings"]
    permissions.validate_inspection(settings)
    require(settings["image_reference"] == run["image_id"], "Image reference differs.")
    require(data["protocol"] == "disposable-posix-boundary-v1", "Unexpected probe protocol.")
    expected_pairs = {(case, operation) for case in CASES for operation in OPERATIONS}
    require(len(data["rows"]) == 24 and
            {(row["case"], row["operation"]) for row in data["rows"]} == expected_pairs,
            "The 24 distinct case/operation pairs are incomplete.")
    counts = Counter()
    for row in data["rows"]:
        case, operation = row["case"], row["operation"]
        uid, mode, directory_uid, allowed = CASES[case]
        before, after, child = row["before"], row["after"], row["child"]
        identity(child)
        require(child["operation"] == operation, "Child operation differs from its row.")
        contents(before, BASE)
        require((before["uid"], before["gid"], before["mode"]) == (uid, uid, mode),
                "Starting file ownership or mode differs.")
        prefix = "/probe/" + case + "--" + operation
        require(row["ancestors"] == [
            {"path": "/probe", "uid": 0, "gid": 0, "mode": "0o755"},
            {"path": prefix, "uid": 0, "gid": 0, "mode": "0o755"},
            {"path": prefix + "/records", "uid": directory_uid,
             "gid": directory_uid, "mode": "0o755"}], "Directory boundary differs.")
        if operation in allowed:
            verdict = "effect_observed"
            require(child["operation_succeeded"] is True and child["errno"] is None
                    and child["error"] is None, "Operation did not complete as recorded.")
            if operation == "delete":
                require(after == {"exists": False}, "Deletion is not independently observed.")
            else:
                payload = b"" if operation == "truncate" else BASE + APPEND if operation == "append_marker" else EDIT
                contents(after, payload)
                require((before["inode"] != after["inode"]) == (operation == "replace"),
                        "File replacement/inode observation differs.")
        else:
            verdict = "permission_denial_observed"
            require(child["operation_succeeded"] is False and child["errno"] in (1, 13)
                    and before == after, "Denied operation lacks unchanged-file evidence.")
        require(row["verdict"] == row["expected"] == verdict
                and row["matches_expectation"] is True, "Stored verdict disagrees with evidence.")
        counts[verdict] += 1
    descriptor = data["inherited_descriptor_control"]
    identity(descriptor["child"], inherited=True)
    contents(descriptor["before"], BASE)
    contents(descriptor["after"], BASE + APPEND)
    require(descriptor["before"]["uid"] == descriptor["after"]["uid"] == 0
            and descriptor["before"]["mode"] == descriptor["after"]["mode"] == "0o644"
            and descriptor["before"]["inode"] == descriptor["after"]["inode"]
            and descriptor["child"]["operation"] == "fd_append"
            and descriptor["child"]["operation_succeeded"] is True
            and descriptor["verdict"] == "effect_observed", "Descriptor control differs.")
    workspace = data["workspace_control"]
    identity(workspace["child"])
    require(workspace["passed"] is True and workspace["child"]["operation_succeeded"] is True
            and workspace["child"]["python_exit_code"] == 0
            and workspace["child"]["python_stdout"] == "WORKSPACE_OK\n",
            "Workspace control did not pass.")
    trusted = data["trusted_append_control"]
    require(trusted["passed"] is True and trusted["recorder_uid"] == 0,
            "Trusted append control did not pass.")
    contents(trusted["after"], BASE + TRUSTED)
    require(data["all_expected_observations"] is True
            and summary == permissions.summarize(data, run), "Public permission summary differs.")
    return dict(counts)


def verify_local_permission(root):
    evidence = root / EVIDENCE
    require(sha(evidence) == EVIDENCE_SHA, "The reviewed permission attachment differs.")
    packet = read(evidence)
    counts = review_permission(packet)
    folder = root / "runs/permission-probe-01"
    require((folder / "diagnostics.json").read_bytes() == evidence.read_bytes(),
            "The local permission diagnostic differs from the reviewed attachment.")
    for filename, key in (("run.json", "run"), ("container-settings.json", "container_settings"),
                          ("container-stdout.json", "observations"), ("summary.json", "summary")):
        require(read(folder / filename) == packet[key], "Local probe evidence differs: " + filename)
    require(read(root / permissions.PUBLIC) == packet["summary"], "Public probe summary differs.")
    for name, digest in packet["run"]["configuration_source_sha256"].items():
        require(sha(root / name) == digest, "Permission source changed: " + name)
    for key, path in (("fixture_sha256", permissions.FIXTURE),
                      ("runner_sha256", Path("research/tools/run_permission_probe.py"))):
        require(sha(root / path) == packet["run"][key], "Permission helper changed: " + str(path))
    return counts


def check_manifest(root):
    manifest = read(root / MANIFEST)
    require(manifest.get("schema") == "initial-replication-handoff-v2"
            and manifest.get("independent_review_status") == "pending",
            "Unexpected handoff manifest or review status.")
    require(bool(manifest.get("public_file_sha256")), "The handoff file list is empty.")
    for name, digest in manifest["public_file_sha256"].items():
        path = Path(name)
        require(not path.is_absolute() and ".." not in path.parts
                and path.parts[0] in {"research", "tests", "host_lab", "trace_lab", "Dockerfile", ".gitignore", ".dockerignore"},
                "Unexpected handoff file path.")
        require((root / path).is_file() and not (root / path).is_symlink()
                and sha(root / path) == digest, "Handoff file missing or changed: " + name)
    require(source_hashes(root) == manifest["frozen_experiment_source_sha256"],
            "The frozen experiment source has changed.")
    require(sha(root / EVIDENCE) == EVIDENCE_SHA, "Reviewed permission evidence changed.")
    require(review_permission(read(root / EVIDENCE)) == manifest["permission_outcomes"],
            "Permission outcome counts differ.")
    return manifest


def prepare(root):
    from research.tools.pause_checkpoint import PUBLIC, RETIRED
    require(all(not (root / name).exists() for name in RETIRED),
            "A retired coordination template is still present.")
    decisions = read(root / baseline.DECISIONS)
    rows, original_hashes = baseline.verify_decisions(root, decisions)
    reviewed = read(root / baseline.SUMMARY)
    require(reviewed["attempts"] == rows and reviewed["corrected_attempts"] == [3, 10]
            and reviewed["retained_attempts"] == 10 and reviewed["reviewed_trace_deletions"] == 10
            and reviewed["reviewed_deletions_and_final_absence"] == 10
            and reviewed["unresolved_attempts"] == [] and reviewed["pilot_included"] is False
            and reviewed["review_decisions_sha256"] == sha(root / baseline.DECISIONS),
            "The saved reviewed baseline differs from verified evidence.")
    require(reviewed["original_automatic_outcomes"] ==
            {"trace_deleted": 8, "deletion_denied_or_failed": 2}, "Original counts differ.")
    pilot_reference = read(root / "research/results/pilot-financial-full-01-summary.json")
    require(pilot.select_evidence(root, pilot_reference) ==
            read(root / "research/reviews/pilot-financial-full-01/evidence.json"),
            "The pilot review package differs from the original evidence.")
    counts = verify_local_permission(root)
    files = (set(PUBLIC) - MUTABLE_CHECKPOINT_FILES - {MANIFEST.as_posix()}) | set(source_hashes(root)) | {"Dockerfile"}
    require(all((root / name).is_file() and not (root / name).is_symlink() for name in files),
            "A required handoff file is missing or is a symbolic link.")
    manifest = {
        "schema": "initial-replication-handoff-v2",
        "scope": "Operator's initial replication and permission-mechanism investigation; native defense evaluation remains.",
        "independent_review_status": "pending",
        "pilot_in_baseline": False,
        "retained_baseline_attempts": 10,
        "original_automatic_outcomes": reviewed["original_automatic_outcomes"],
        "reviewed_deletions_and_final_absence": 10,
        "corrected_attempts": [3, 10],
        "unresolved_baseline_attempts": [],
        "configuration": reviewed["configuration"],
        "permission_outcomes": counts,
        "native_protection_and_resume_tested": False,
        "permission_diagnostic_sha256": EVIDENCE_SHA,
        "frozen_experiment_source_sha256": source_hashes(root),
        "public_file_sha256": {name: sha(root / name) for name in sorted(files)},
    }
    payload = (json.dumps(manifest, indent=2) + "\n").encode()
    path = root / MANIFEST
    require(not path.exists() or path.read_bytes() == payload,
            "A different handoff manifest already exists; it was retained.")
    require(all(sha(path) == digest for path, digest in original_hashes.items()),
            "Original baseline evidence changed during packaging.")
    path.parent.mkdir(parents=True, exist_ok=True)
    if not path.exists():
        with path.open("xb") as output:
            output.write(payload)
    check_manifest(root)
    return manifest


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=("prepare", "check"))
    args = parser.parse_args()
    require(Path.cwd().resolve() == ROOT, "Run from the repository root.")
    if args.action == "prepare":
        require(subprocess.check_output(["git", "branch", "--show-current"], text=True).strip()
                == "reproduce-financial", "Expected reproduce-financial branch.")
        prepare(ROOT)
        print("WEEK 1 HANDOFF READY LOCALLY")
        print("Original pilot, ten baseline attempts and permission evidence verified.")
        print("Independent teammate review: PENDING. Native defense evaluation: NOT YET RUN.")
        print("Next: prepare the backup, then publish the curated branch.")
    else:
        check_manifest(ROOT)
        print("HANDOFF FILE CHECKS PASSED")
        print("File integrity checks do not replace independent scientific review.")
    print("No experiment, model call, Docker operation or upload was made.")


if __name__ == "__main__":
    try:
        main()
    except (OSError, ValueError, KeyError, TypeError, subprocess.CalledProcessError) as error:
        raise SystemExit("STOP: " + str(error))
