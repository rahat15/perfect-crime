"""Tests for the probe-02 variant wrapper: prediction data, derived views, sysctl guard, committed
variant records, and root-only live checks."""

import copy
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import tempfile
import time
import unittest

from research.tools import permission_probe_v2_fixture as fixture
from research.tools import run_permission_probe_v2 as runner
from research.tools import run_permission_probe_v2_variants as variants

ROOT = Path(__file__).resolve().parents[1]
OUTPUT = ROOT / variants.OUTPUT
SUMMARY = OUTPUT / variants.SUMMARY_NAME
README = OUTPUT / "README.md"
WRAPPER = Path(variants.__file__)
COMMITTED = json.loads((ROOT / variants.COMMITTED_EVIDENCE).read_text())
SIGNATURE = runner.verdict_signature(COMMITTED)


def normalized(value):
    return json.loads(json.dumps(value))


class PredictionDataTests(unittest.TestCase):
    def test_every_variant_is_well_formed(self):
        for name, spec in variants.VARIANTS.items():
            with self.subTest(name):
                self.assertEqual(set(spec), {"description", "root", "alternate_root", "fill", "sysctls",
                                             "predicted_differences", "prediction_basis"})
                self.assertIn(spec["root"], ("tmpfs", "overlay_tmpfs", "overlay_ext4", "bind_ext4", "plain"))
                self.assertIn(spec["fill"], ("tmpfs", "bind_tmpfs"))
                self.assertLessEqual(set(spec["sysctls"]), set(variants.SYSCTLS))
                self.assertGreater(len(spec["prediction_basis"]), 60)
        self.assertEqual(sum(bool(spec["sysctls"]) for spec in variants.VARIANTS.values()), 4)
        self.assertIn("frozen fixture", variants.NOT_RUN_VARIANTS["bind_mount_separate_records_workspace"])

    def test_predicted_cells_exist_and_start_from_the_committed_verdict(self):
        for name, spec in variants.VARIANTS.items():
            cells = [item["cell"] for item in spec["predicted_differences"]]
            self.assertEqual(len(cells), len(set(cells)), name)
            for item in spec["predicted_differences"]:
                with self.subTest(variant=name, cell=item["cell"]):
                    self.assertIn(item["cell"], SIGNATURE)
                    self.assertEqual(SIGNATURE[item["cell"]][0], item["from"])
                    self.assertNotEqual(item["from"], item["to"])
                    self.assertGreater(len(item["why"]), 40)

    def test_hardlink_prediction_is_exactly_the_cells_the_fixture_codes_as_sysctl_dependent(self):
        coded = {variants.OP % (case, "hardlink_create") for case, codes in fixture.EXPECTED_CODES.items()
                 if codes["hardlink_create"] == "H"}
        predicted = {item["cell"] for item in variants.VARIANTS["protected_hardlinks_0"]["predicted_differences"]}
        self.assertEqual(predicted, coded)
        self.assertEqual(len(predicted), 8)
        for other in ("protected_regular_1", "protected_regular_2", "protected_symlinks_1", "overlayfs_on_tmpfs"):
            self.assertEqual(variants.VARIANTS[other]["predicted_differences"], [])

    def test_effect_predictions(self):
        default = {"protected_regular": 0, "protected_hardlinks": 1, "protected_symlinks": 0}
        creat, link = "regular_0666_recorder_o_creat_append", "symlink_recorder_o_creat_append"
        self.assertEqual(variants.predicted_effect(creat, "sticky_1777", default), "appended_into_agent_file")
        self.assertEqual(variants.predicted_effect(creat, "sticky_1777", dict(default, protected_regular=1)),
                         "refused:EACCES")
        self.assertEqual(variants.predicted_effect(creat, "sticky_1770_shared_group",
                                                   dict(default, protected_regular=1)), "appended_into_agent_file")
        self.assertEqual(variants.predicted_effect(creat, "sticky_1770_shared_group",
                                                   dict(default, protected_regular=2)), "refused:EACCES")
        self.assertEqual(variants.predicted_effect(link, "sticky_1777", dict(default, protected_symlinks=1)),
                         "refused:EACCES")
        self.assertEqual(variants.predicted_effect(link, "sticky_1770_shared_group",
                                                   dict(default, protected_symlinks=1)), "appended_into_agent_file")
        self.assertEqual(variants.predicted_effect("regular_0666_recorder_append_without_o_creat", "sticky_1777",
                                                   dict(default, protected_regular=2)), "appended_into_agent_file")
        for control in variants.EFFECT_CONTROLS:
            if control.endswith("_o_creat_excl"):
                self.assertEqual(variants.predicted_effect(control, "sticky_1777", default), "refused:EEXIST")
        for control, directory in variants.EFFECT_REFUSED_WHEN:
            self.assertIn(control, variants.EFFECT_CONTROLS)
            self.assertIn(directory, variants.EFFECT_DIRECTORIES)


class DerivedViewTests(unittest.TestCase):
    def test_identical_evidence_has_no_differences(self):
        analysis = variants.difference_analysis(COMMITTED, COMMITTED, [])
        self.assertEqual((analysis["recorded_cells"], analysis["executed_in_both"], analysis["not_run_in_both"]),
                         (495, 467, 28))
        self.assertTrue(analysis["same_coverage"])
        self.assertEqual(analysis["differences"], [])
        self.assertTrue(analysis["all_predictions_held"])

    def test_predicted_unpredicted_and_missing_differences_are_separated(self):
        changed = copy.deepcopy(COMMITTED)
        rows = {(row["case"], row["operation"]): row for row in changed["observations"]["rows"]}
        rows["sticky_1777_dir_recorder_file", "hardlink_create"].update(verdict=fixture.E)
        rows["sticky_1777_dir_recorder_file", "hardlink_create"]["child"]["errno"] = None
        rows["recorder_owned_agent_readonly", "delete"].update(verdict=fixture.E)
        rows["acl_agent_read_only", "rewrite"]["child"]["errno"] = 1
        suppression = changed["observations"]["suppression_controls"][1]
        suppression["verdict"] = fixture.N
        predictions = variants.VARIANTS["protected_hardlinks_0"]["predicted_differences"]
        analysis = variants.difference_analysis(COMMITTED, changed, predictions)
        by_cell = {entry["cell"]: entry for entry in analysis["differences"]}
        self.assertTrue(by_cell["op/sticky_1777_dir_recorder_file/hardlink_create"]["predicted"])
        unexplained = by_cell["op/recorder_owned_agent_readonly/delete"]
        self.assertFalse(unexplained["predicted"])
        self.assertIn("UNEXPLAINED", unexplained["flag"])
        self.assertEqual(by_cell["op/acl_agent_read_only/rewrite"]["kind"], "same_verdict_other_detail_changed")
        self.assertEqual(len(analysis["not_run_vs_measured"]), 1)
        self.assertEqual(len(analysis["predicted_but_not_observed"]), 7)
        self.assertFalse(analysis["all_predictions_held"])
        self.assertEqual(analysis["verdict_changed"], ["op/recorder_owned_agent_readonly/delete",
                                                       "op/sticky_1777_dir_recorder_file/hardlink_create"])

    def test_layout_lists_recomputed_from_the_committed_evidence(self):
        lists = variants.layout_lists(COMMITTED["observations"])
        first = lists["tampering_denied_and_discriminating_proxies_kept"]
        self.assertEqual(first["holds"], runner.protecting_layouts(COMMITTED["observations"]))
        self.assertEqual(len(first["holds"]), 6)
        self.assertEqual(first["undetermined"], [])
        strict = lists["and_resists_every_suppression_operation"]
        self.assertEqual((strict["holds"], strict["undetermined"]), ([], []))
        self.assertEqual(len(strict["fails"]), 6)
        self.assertEqual(lists["and_resists_precreate_and_separate_filesystem_fill"]["holds"],
                         ["recorder_owned_agent_readonly", "recorder_owned_no_agent_access",
                          "append_only_recorder_owned", "acl_agent_read_only"])
        self.assertEqual(set(lists["suppression_table"]), set(fixture.CASES))
        self.assertEqual(lists["suppression_table"]["sticky_1777_dir_recorder_file"]
                         ["precreate_next_session_name"], fixture.S)

    def test_a_layout_losing_a_discriminating_proxy_or_gaining_a_tamper_fails_the_first_list(self):
        changed = copy.deepcopy(COMMITTED["observations"])
        for row in changed["legit_controls"]:
            if row["case"] == "acl_agent_read_only" and row["control"] == "recorder_append":
                row.update(passed=False, outcome="permission_denied")
        for row in changed["rows"]:
            if row["case"] == "sticky_1777_dir_recorder_file" and row["operation"] == "delete":
                row["verdict"] = fixture.E
        first = variants.layout_lists(changed)["tampering_denied_and_discriminating_proxies_kept"]
        failed = [item["layout"] for item in first["fails"]]
        self.assertIn("acl_agent_read_only", failed)
        self.assertIn("sticky_1777_dir_recorder_file", failed)
        self.assertIn("recorder_owned_agent_readonly", first["holds"])

    def test_cells_not_executed_make_a_variant_layout_undetermined_never_resisting(self):
        changed = copy.deepcopy(COMMITTED["observations"])
        for row in changed["suppression_controls"]:
            if row["operation"].startswith("fill_") and row["verdict"] != fixture.N:
                row.update(verdict=fixture.N, matches_expectation=None,
                           not_run_reason="no dedicated size-limited fill filesystem was provided")
        for row in changed["rows"]:
            if row["case"] == "append_only_recorder_owned" and row["operation"] == "rewrite":
                row.update(verdict=fixture.N, matches_expectation=None, not_run_reason="fixture setup failed")
        lists = variants.layout_lists(changed)
        first = lists["tampering_denied_and_discriminating_proxies_kept"]
        self.assertEqual([item["layout"] for item in first["undetermined"]], ["append_only_recorder_owned"])
        self.assertNotIn("append_only_recorder_owned", first["holds"])
        for name in ("and_resists_every_suppression_operation",
                     "and_resists_precreate_and_separate_filesystem_fill"):
            self.assertEqual(lists[name]["holds"], [], name)
            self.assertEqual([item["layout"] for item in lists[name]["undetermined"]],
                             ["recorder_owned_agent_readonly", "recorder_owned_no_agent_access",
                              "acl_agent_read_only"], name)
            self.assertEqual([item["layout"] for item in lists[name]["fails"]],
                             ["sticky_1777_dir_recorder_file", "sticky_1770_shared_group_dir"], name)


class SysctlGuardTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.directory = Path(temporary.name) / "fs"
        self.directory.mkdir()
        for name, value in zip(variants.SYSCTLS, (0, 1, 0)):
            (self.directory / name).write_text("%d\n" % value)
        self.marker = Path(temporary.name) / "marker.json"
        self.guard = variants.SysctlGuard(self.directory, self.marker)
        self.default = {"protected_regular": 0, "protected_hardlinks": 1, "protected_symlinks": 0}

    def test_apply_sets_marker_and_restore_removes_it(self):
        during = self.guard.apply({"protected_hardlinks": 0, "protected_regular": 2})
        self.assertEqual(during, {"protected_regular": 2, "protected_hardlinks": 0, "protected_symlinks": 0})
        self.assertEqual(json.loads(self.marker.read_text())["original"], self.default)
        self.assertEqual(self.guard.restore(), self.default)
        self.assertFalse(self.marker.exists())
        self.assertEqual(self.guard.restore(), self.default, "restore is idempotent")

    def test_no_change_writes_no_marker(self):
        self.assertEqual(self.guard.apply({}), self.default)
        self.assertFalse(self.marker.exists())
        self.assertEqual(self.guard.restore(), self.default)

    def test_restore_runs_in_finally_even_when_the_body_raises(self):
        with self.assertRaises(variants.Interrupted):
            try:
                self.guard.apply({"protected_symlinks": 1})
                raise variants.Interrupted("signal")
            finally:
                self.guard.restore()
        self.assertEqual(self.guard.read(), self.default)
        self.assertFalse(self.marker.exists())

    def test_stale_marker_refuses_to_start_and_can_be_recovered(self):
        self.guard.apply({"protected_hardlinks": 0})
        fresh = variants.SysctlGuard(self.directory, self.marker)
        with self.assertRaisesRegex(ValueError, "unrestored"):
            fresh.refuse_if_stale()
        with self.assertRaisesRegex(ValueError, "unrestored"):
            fresh.apply({"protected_regular": 1})
        self.assertEqual(fresh.read()["protected_regular"], 0, "nothing was changed by the refused start")
        self.assertEqual(fresh.restore_from_marker(), self.default)
        self.assertFalse(self.marker.exists())
        fresh.refuse_if_stale()

    def test_marker_survives_when_values_cannot_be_restored(self):
        self.guard.apply({"protected_hardlinks": 0})
        os.chmod(self.directory / "protected_hardlinks", 0o444)
        writer = self.guard._write
        self.guard._write = lambda name, value: (_ for _ in ()).throw(PermissionError(13, "refused"))
        with self.assertRaises(PermissionError):
            self.guard.restore()
        self.assertTrue(self.marker.exists())
        self.guard._write = writer
        os.chmod(self.directory / "protected_hardlinks", 0o644)
        self.assertEqual(self.guard.restore(), self.default)

    def test_unknown_or_rejected_values(self):
        with self.assertRaisesRegex(ValueError, "Unknown sysctl"):
            self.guard.apply({"protected_fifos": 1})
        self.guard._write = lambda name, value: None  # kernel silently ignoring the write
        with self.assertRaisesRegex(ValueError, "did not take"):
            self.guard.apply({"protected_regular": 1})
        self.assertTrue(self.marker.exists())


@unittest.skipUnless(SUMMARY.is_file() and README.is_file(), "variant results have not been recorded")
class CommittedVariantRecordTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.summary = json.loads(SUMMARY.read_text())
        cls.entries = cls.summary["variants"]

    def test_every_variant_is_recorded_with_the_frozen_tool_hashes(self):
        self.assertEqual(list(self.entries), list(variants.VARIANTS))
        self.assertEqual(self.summary["not_run_variants"], variants.NOT_RUN_VARIANTS)
        for name, entry in self.entries.items():
            with self.subTest(name):
                self.assertIn(entry["status"], ("executed", "not_run"))
                if entry["status"] == "not_run":
                    self.assertTrue(entry["not_run_reason"])
                    continue
                self.assertEqual(entry["fixture_sha256"], runner.sha(ROOT / runner.FIXTURE))
                self.assertEqual(entry["runner_sha256"], runner.sha(Path(runner.__file__)))
                self.assertEqual(entry["wrapper_sha256"], runner.sha(WRAPPER))
                self.assertEqual(entry["predicted_differences"],
                                 normalized(variants.VARIANTS[name]["predicted_differences"]))
                self.assertEqual(entry["requested_sysctls"], variants.VARIANTS[name]["sysctls"])
                recorded = entry["derived"]["environment"]["sysctl_fs"]
                for sysctl, value in entry["requested_sysctls"].items():
                    self.assertEqual(recorded[sysctl], value)
                self.assertEqual(entry["setup"]["sysctl"]["restored"], entry["setup"]["sysctl"]["original"])
                self.assertIn(name, entry["regenerate_command"])

    def test_reference_block_derives_from_the_committed_probe_02_evidence(self):
        expected = variants.reference_record(COMMITTED, variants.COMMITTED_EVIDENCE)
        self.assertEqual(self.summary["committed_reference"], normalized(expected))

    def test_comparison_files_equal_the_summary_and_the_committed_runner_compare(self):
        for name, entry in self.entries.items():
            if entry["status"] != "executed":
                continue
            with self.subTest(name):
                stored = json.loads((OUTPUT / entry["comparison_file"]).read_text())
                self.assertEqual(stored, entry["comparison"])
                analysis = entry["derived"]["difference_analysis"]
                self.assertEqual(sorted(stored["verdict_differences_among_executed_in_both"]),
                                 sorted(analysis["verdict_changed"] + analysis["same_verdict_other_detail_changed"]))
                self.assertEqual(sorted(stored["executed_only_in_a"] + stored["executed_only_in_b"]),
                                 sorted(analysis["not_run_vs_measured"]))
                self.assertEqual((stored["recorded_cells"], stored["executed_in_both"], stored["not_run_in_both"]),
                                 (analysis["recorded_cells"], analysis["executed_in_both"],
                                  analysis["not_run_in_both"]))
                self.assertEqual(stored["same_coverage"], analysis["same_coverage"])
                self.assertEqual(entry["derived"]["coverage"]["total"]["recorded"], 495)
                for name in ("identical", "identical_verdicts"):
                    self.assertNotIn(name, stored)

    def test_summary_entries_derive_from_the_committed_variant_evidence_files(self):
        kept = [name for name, entry in self.entries.items() if entry.get("evidence_file")]
        self.assertTrue(kept, "at least one variant evidence file is committed")
        for name in kept:
            entry = self.entries[name]
            path = OUTPUT / entry["evidence_file"]
            with self.subTest(name):
                self.assertEqual(runner.sha(path), entry["evidence_sha256"])
                evidence = json.loads(path.read_text())
                self.assertEqual(entry["derived"], normalized(variants.derive(evidence, COMMITTED, name)))
                self.assertEqual(entry["comparison"], normalized(runner.compare(COMMITTED, evidence)))
                self.assertEqual((evidence["run"]["status"], evidence["run"]["cleanup_verified"]),
                                 ("finished", True))
                self.assertEqual(evidence["run"]["variant"], name)

    def test_evidence_is_kept_exactly_for_variants_that_differ(self):
        for name, entry in self.entries.items():
            if entry["status"] != "executed":
                continue
            differs = bool(entry["derived"]["difference_analysis"]["differences"])
            with self.subTest(name):
                self.assertEqual(entry["evidence_file"] is not None, differs)
                self.assertEqual((OUTPUT / ("evidence-%s.json" % name)).exists(), differs)
                self.assertEqual(len(entry["evidence_sha256"]), 64)

    def test_effect_control_files_match_the_summary_and_their_predictions(self):
        for name, entry in self.entries.items():
            if entry["status"] != "executed":
                continue
            stored = json.loads((OUTPUT / entry["effect_controls_file"]).read_text())
            with self.subTest(name):
                self.assertEqual(len(stored["rows"]),
                                 len(variants.EFFECT_CONTROLS) * len(variants.EFFECT_DIRECTORIES))
                for row in stored["rows"]:
                    key = "%s/%s" % (row["directory"], row["control"])
                    self.assertEqual(entry["effect_controls"][key]["outcome"], row["outcome"])
                    self.assertEqual(row["predicted"], variants.predicted_effect(
                        row["control"], row["directory"], stored["sysctls_during"]))
                    self.assertEqual(row["matches_prediction"], row["outcome"] == row["predicted"])
                    self.assertTrue(row["agent_child"]["identity_valid"] and row["recorder_child"]["identity_valid"])
                    self.assertEqual(row["recorder_child"]["uid"], [fixture.RECORDER_UID] * 3)
                    self.assertEqual(row["agent_child"]["uid"], [fixture.AGENT_UID] * 3)

    def test_first_principles_hardlink_variant(self):
        entry = self.entries["protected_hardlinks_0"]
        if entry["status"] != "executed":
            self.skipTest("hard-link variant not executed")
        evidence = json.loads((OUTPUT / entry["evidence_file"]).read_text())
        self.assertEqual(evidence["observations"]["environment"]["sysctl_fs"]["protected_hardlinks"], 0)
        rows = {(row["case"], row["operation"]): row for row in evidence["observations"]["rows"]}
        linked = rows["recorder_owned_agent_readonly", "hardlink_create"]
        self.assertEqual(linked["verdict"], fixture.E)
        self.assertEqual(linked["after"]["target"]["link_count"], 2)
        self.assertEqual(linked["after"]["target"]["sha256"], fixture.digest(fixture.BASE))
        self.assertEqual(linked["after"]["target"]["uid"], fixture.RECORDER_UID)
        self.assertIn("workspace/hardlink.jsonl", linked["after"]["original_inode_paths"])
        self.assertEqual(rows["recorder_owned_no_agent_access", "hardlink_create"]["verdict"], fixture.D)
        self.assertEqual(rows["append_only_recorder_owned", "hardlink_create"]["child"]["errno"], 1)
        self.assertEqual(rows["recorder_owned_agent_readonly", "rewrite"]["verdict"], fixture.D)

    def test_readme_cites_each_variant_and_the_checkable_caveats(self):
        text = README.read_text()
        for name, entry in self.entries.items():
            self.assertIn("`%s`" % name, text)
            if entry["status"] == "executed":
                self.assertIn(entry["evidence_sha256"], text)
        for phrase in ("cannot be independently verified", "not native Codex", "--keep-evidence all",
                       "bind_mount_separate_records_workspace", "0 1 0", "effect controls", "undetermined",
                       "permission-probe-02-docker"):
            self.assertIn(phrase, text)


class LiveVariantTests(unittest.TestCase):
    def leftovers(self):
        return sorted(name for name in os.listdir(tempfile.gettempdir()) if name.startswith("cse227-probe-v2"))

    @unittest.skipUnless(os.geteuid() == 0, "variant runs need root (mounts, sysctls, dropping UIDs)")
    def test_control_variant_reproduces_the_committed_evidence_and_leaves_nothing(self):
        guard = variants.SysctlGuard()
        before, stray = guard.read(), self.leftovers()
        with tempfile.TemporaryDirectory() as directory:
            result = subprocess.run([sys.executable, str(WRAPPER), "--run", "wrapper_control_tmpfs", "--runs", "1",
                                     "--output-dir", directory], capture_output=True, text=True, timeout=300,
                                    cwd=str(ROOT))
            if result.returncode != 0 and any(text in result.stderr + result.stdout
                                              for text in ("private mount namespace", "mount failed")):
                self.skipTest("cannot mount here: " + (result.stderr or result.stdout)[-200:])
            self.assertEqual(result.returncode, 0, result.stderr[-800:] + result.stdout[-800:])
            entry = json.loads((Path(directory) / variants.SUMMARY_NAME).read_text())["variants"][
                "wrapper_control_tmpfs"]
            self.assertEqual(entry["status"], "executed", entry.get("not_run_reason"))
            analysis = entry["derived"]["difference_analysis"]
            self.assertEqual((analysis["recorded_cells"], analysis["executed_in_both"]), (495, 467))
            self.assertTrue(analysis["same_coverage"])
            self.assertEqual(analysis["differences"], [])
            lists = entry["derived"]["layout_lists"]
            self.assertEqual(lists["and_resists_every_suppression_operation"]["holds"], [])
            self.assertEqual(lists["and_resists_every_suppression_operation"]["undetermined"], [])
            self.assertTrue(entry["derived"]["all_evaluated_observations_match_fixture_expectation"])
            self.assertTrue(all(item["matches_prediction"] for item in entry["effect_controls"].values()))
            self.assertIsNone(entry["evidence_file"])
            self.assertFalse((Path(directory) / "evidence-wrapper_control_tmpfs.json").exists())
        self.assertEqual(guard.read(), before)
        self.assertFalse(guard.marker.exists())
        self.assertEqual(self.leftovers(), stray)
        self.assertNotIn("cse227-probe-v2-variant", Path("/proc/self/mountinfo").read_text())

    @unittest.skipUnless(os.geteuid() == 0, "variant runs need root (mounts, sysctls, dropping UIDs)")
    def test_sigterm_during_a_sysctl_variant_restores_the_sysctl_and_leaves_nothing(self):
        guard = variants.SysctlGuard()
        before, stray = guard.read(), self.leftovers()
        if before["protected_hardlinks"] != 1:
            self.skipTest("protected_hardlinks is not 1 on this machine")
        with tempfile.TemporaryDirectory() as directory:
            process = subprocess.Popen([sys.executable, str(WRAPPER), "--run", "protected_hardlinks_0", "--runs", "1",
                                        "--output-dir", directory], stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                       text=True, cwd=str(ROOT))
            changed = False
            for _ in range(300):
                if process.poll() is not None:
                    break
                if guard.read()["protected_hardlinks"] == 0:
                    changed = True
                    break
                time.sleep(0.05)
            if not changed:
                process.kill()
                out, err = process.communicate()
                self.skipTest("the variant never changed the sysctl here: " + (err or out)[-200:])
            self.assertTrue(guard.marker.exists(), "marker exists while the sysctl is changed")
            process.send_signal(signal.SIGTERM)
            out, err = process.communicate(timeout=120)
            self.assertNotEqual(process.returncode, 0)
            self.assertIn("Sysctls restored and verified", out)
        self.assertEqual(guard.read(), before)
        self.assertFalse(guard.marker.exists())
        self.assertEqual(self.leftovers(), stray)
        self.assertNotIn("cse227-probe-v2-variant", Path("/proc/self/mountinfo").read_text())


if __name__ == "__main__":
    unittest.main()
