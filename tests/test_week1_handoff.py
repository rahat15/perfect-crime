"""Offline evidence and publication checks; no model, Docker or network calls."""

import copy
import hashlib
import json
import io
from contextlib import redirect_stdout
from pathlib import Path
import shutil
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from research.tools import finalize_week1 as handoff
from research.tools import pause_checkpoint as checkpoint


class PermissionEvidenceReviewTests(unittest.TestCase):
    def setUp(self):
        self.packet = handoff.read(handoff.ROOT / handoff.EVIDENCE)

    def test_saved_measurements_and_source_hashes_match(self):
        self.assertEqual(handoff.sha(handoff.ROOT / handoff.EVIDENCE), handoff.EVIDENCE_SHA)
        self.assertEqual(handoff.review_permission(self.packet),
                         {"effect_observed": 11, "permission_denial_observed": 13})
        for name, digest in self.packet["run"]["configuration_source_sha256"].items():
            self.assertEqual(handoff.sha(handoff.ROOT / name), digest)

    def test_duplicated_case_cannot_hide_missing_operation(self):
        self.packet["observations"]["rows"][1] = copy.deepcopy(self.packet["observations"]["rows"][0])
        with self.assertRaisesRegex(ValueError, "distinct case/operation"):
            handoff.review_permission(self.packet)

    def test_retained_privilege_or_handle_is_rejected(self):
        for key, value in (("CapEff", "1"), ("CapPrm", "1"), ("CapAmb", "1"), ("NoNewPrivs", "0")):
            packet = copy.deepcopy(self.packet)
            packet["observations"]["rows"][0]["child"]["identity"]["status"][key] = value
            with self.subTest(key=key), self.assertRaisesRegex(ValueError, "retained privileges"):
                handoff.review_permission(packet)
        self.packet["observations"]["rows"][0]["child"]["identity"]["inherited_probe_fds"] = [{"fd": 3}]
        with self.assertRaisesRegex(ValueError, "inherited probe handle"):
            handoff.review_permission(self.packet)

    def test_denial_without_unchanged_snapshot_is_rejected(self):
        row = next(row for row in self.packet["observations"]["rows"]
                   if row["verdict"] == "permission_denial_observed")
        row["after"]["sha256"] = "0" * 64
        with self.assertRaisesRegex(ValueError, "unchanged-file"):
            handoff.review_permission(self.packet)

    def test_writable_ancestor_in_protected_case_is_rejected(self):
        self.packet["observations"]["rows"][-1]["ancestors"][0]["mode"] = "0o777"
        with self.assertRaisesRegex(ValueError, "Directory boundary"):
            handoff.review_permission(self.packet)

    def test_success_claim_without_effect_is_rejected(self):
        row = next(row for row in self.packet["observations"]["rows"] if row["operation"] == "delete")
        row["after"] = copy.deepcopy(row["before"])
        with self.assertRaisesRegex(ValueError, "Deletion is not independently"):
            handoff.review_permission(self.packet)

    def test_inherited_handle_wrong_target_is_rejected(self):
        self.packet["observations"]["inherited_descriptor_control"]["child"]["identity"]["inherited_probe_fds"][0]["target"] = "/elsewhere"
        with self.assertRaisesRegex(ValueError, "unexpected file"):
            handoff.review_permission(self.packet)

    def test_cleanup_and_host_mount_must_be_safe(self):
        packet = copy.deepcopy(self.packet)
        packet["run"]["cleanup_verified"] = False
        with self.assertRaisesRegex(ValueError, "cleanup was incomplete"):
            handoff.review_permission(packet)
        self.packet["container_settings"]["binds"] = ["/private:/probe"]
        with self.assertRaisesRegex(ValueError, "host bind mount"):
            handoff.review_permission(self.packet)


class HandoffPublicationTests(unittest.TestCase):
    def test_full_local_handoff_and_verified_backup_preserve_sources(self):
        from tests.test_baseline_finalization import BaselineFinalizationTests
        from tests.test_pilot_review_package import PilotReviewPackageTests
        from research.tools import finalize_baseline_review as baseline
        baseline_fixture = BaselineFinalizationTests()
        baseline_fixture.setUp()
        self.addCleanup(baseline_fixture.doCleanups)
        pilot_fixture = PilotReviewPackageTests()
        pilot_fixture.setUp()
        self.addCleanup(pilot_fixture.doCleanups)
        root = baseline_fixture.root
        for name in checkpoint.PUBLIC:
            if name == handoff.MANIFEST.as_posix():
                continue
            destination = root / name
            destination.parent.mkdir(parents=True, exist_ok=True)
            source = handoff.ROOT / name
            if source.is_file() and not destination.exists():
                shutil.copyfile(source, destination)
            elif not destination.exists():
                destination.write_text("Synthetic test fixture only.\n")
        for name in handoff.read(handoff.ROOT / handoff.EVIDENCE)["run"]["configuration_source_sha256"]:
            destination = root / name
            destination.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(handoff.ROOT / name, destination)
        shutil.copytree(pilot_fixture.folder, root / handoff.pilot.PILOT)
        grader = root / "host_lab/anonymization_loop.py"
        review_path = root / handoff.pilot.PILOT / ("report-reviewed-" + handoff.pilot.VERSION + ".json")
        review = handoff.read(review_path)
        review["research_review"]["grader_sha256"] = handoff.sha(grader)
        checkpoint.save_json(review_path, review)
        checkpoint.save_json(root / "research/results/pilot-financial-full-01-summary.json", pilot_fixture.reference)
        checkpoint.save_json(root / "research/reviews/pilot-financial-full-01/evidence.json",
                             handoff.pilot.select_evidence(root, pilot_fixture.reference))
        packet = handoff.read(root / handoff.EVIDENCE)
        folder = root / "runs/permission-probe-01"
        folder.mkdir(parents=True)
        for name, key in (("run.json", "run"), ("container-settings.json", "container_settings"),
                          ("container-stdout.json", "observations"), ("summary.json", "summary")):
            checkpoint.save_json(folder / name, packet[key])
        (folder / "container-stderr.log").write_text("Synthetic test fixture only.\n")
        shutil.copyfile(root / handoff.EVIDENCE, folder / "diagnostics.json")
        checkpoint.save_json(root / handoff.permissions.PUBLIC, packet["summary"])
        plan_path = root / baseline.BATCH / "plan.json"
        plan = handoff.read(plan_path)
        plan["source_sha256"] = handoff.source_hashes(root)
        checkpoint.save_json(plan_path, plan)
        rows, originals = baseline.verify_decisions(root, baseline_fixture.decisions)
        (root / baseline.SUMMARY).unlink()
        (root / baseline.DECISIONS.parent / "README.md").unlink()
        baseline.write_outputs(root, baseline_fixture.decisions, rows, originals)
        with redirect_stdout(io.StringIO()):
            manifest = handoff.prepare(root)
            self.assertEqual(handoff.prepare(root), manifest)
            with tempfile.TemporaryDirectory() as backup_dir, \
                 patch.object(checkpoint, "git", side_effect=lambda *args, **kw: SimpleNamespace(
                     stdout="" if args[0] == "ls-files" else "test-head\n")):
                checkpoint.prepare(root, Path(backup_dir))
                state = handoff.read(root / checkpoint.STATE)
                self.assertTrue(state["backup_verified"])
                self.assertTrue(state["week1_handoff_prepared"])
                self.assertFalse(state["week1_operator_work_complete"])
                self.assertEqual(handoff.check_manifest(root), manifest)
        self.assertTrue(all(handoff.sha(path) == digest for path, digest in originals.items()))

    def test_changed_prepared_handoff_blocks_network(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            filename = "research/README.md"
            path = root / filename
            path.parent.mkdir()
            path.write_text("prepared")
            digest = checkpoint.sha256(path)
            archive = root / "backup.tar.gz"
            archive.write_bytes(b"test backup placeholder")
            checkpoint.save_json(root / checkpoint.STATE, {
                "backup_verified": True, "backup_archive": str(archive),
                "prepared_head": "head", "public_files": [filename],
                "public_sha256": {filename: digest}, "week1_handoff_prepared": True,
            })
            path.write_text("changed")
            with patch.object(checkpoint, "git", return_value=SimpleNamespace(stdout="head\n")), \
                 patch.object(checkpoint, "run") as network:
                with self.assertRaisesRegex(SystemExit, "Prepared research files changed"):
                    checkpoint.publish(root)
                network.assert_not_called()

    def test_manifest_checks_frozen_sources_and_file_drift(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            path = root / handoff.EVIDENCE
            path.parent.mkdir(parents=True)
            path.write_bytes((handoff.ROOT / handoff.EVIDENCE).read_bytes())
            manifest = {"schema": "initial-replication-handoff-v2", "independent_review_status": "pending",
                        "public_file_sha256": {handoff.EVIDENCE.as_posix(): handoff.sha(path)},
                        "frozen_experiment_source_sha256": {"source": "unchanged"},
                        "permission_outcomes": {"effect_observed": 11, "permission_denial_observed": 13}}
            checkpoint.save_json(root / handoff.MANIFEST, manifest)
            with patch.object(handoff, "source_hashes", return_value={"source": "unchanged"}):
                self.assertEqual(handoff.check_manifest(root), manifest)
                path.write_bytes(path.read_bytes() + b" ")
                with self.assertRaisesRegex(ValueError, "missing or changed"):
                    handoff.check_manifest(root)

    def test_curated_publication_excludes_raw_runs_and_credentials(self):
        self.assertIn(handoff.EVIDENCE.as_posix(), checkpoint.PUBLIC)
        self.assertIn(handoff.MANIFEST.as_posix(), checkpoint.PUBLIC)
        for name in checkpoint.PUBLIC:
            self.assertFalse(name.startswith("runs/"))
            self.assertNotIn("auth.json", name)
            self.assertNotIn(".env", Path(name).name)


if __name__ == "__main__":
    unittest.main()
