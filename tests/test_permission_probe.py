"""Offline helper tests; the cross-account Docker matrix runs separately."""

import copy
import errno
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

from research.tools import permission_probe_fixture as fixture
from research.tools import run_permission_probe as runner


class PermissionProbeTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.target = self.root / "synthetic.jsonl"
        self.target.write_bytes(fixture.BASE)

    def local_child(self, operation, descriptor=None):
        request = {"operation": operation, "target": str(self.target), "workspace": str(self.root)}
        if descriptor is not None:
            request["fd"] = descriptor
        completed = subprocess.run([sys.executable, "-I", "-c", fixture.CHILD, json.dumps(request)],
                                   pass_fds=() if descriptor is None else (descriptor,),
                                   capture_output=True, text=True, timeout=10)
        self.assertEqual(completed.returncode, 0, completed.stderr)
        return json.loads(completed.stdout)

    @staticmethod
    def result(success=True, error=None):
        return {"identity": {"uid": [1000] * 3, "gid": [1000] * 3, "groups": [],
                             "status": {"CapEff": "0", "CapPrm": "0", "CapAmb": "0", "NoNewPrivs": "1"},
                             "inherited_probe_fds": []},
                "operation_succeeded": success, "errno": error}

    def test_rewrite_effect_is_checked_from_file_contents(self):
        before = fixture.snapshot(self.target)
        result = self.local_child("rewrite")
        self.assertTrue(result["operation_succeeded"])
        self.assertEqual(self.target.read_bytes(), fixture.EDIT)
        self.assertTrue(fixture.effect_observed("rewrite", before, fixture.snapshot(self.target)))

    @unittest.skipIf(os.geteuid() == 0, "This local check requires an unprivileged test account")
    def test_readonly_file_denies_write_but_owner_can_restore_mode(self):
        self.target.chmod(0o444)
        result = self.local_child("rewrite")
        self.assertFalse(result["operation_succeeded"])
        self.assertEqual(result["errno"], errno.EACCES)
        self.assertEqual(self.target.read_bytes(), fixture.BASE)
        result = self.local_child("chmod_then_rewrite")
        self.assertTrue(result["operation_succeeded"])
        self.assertEqual(self.target.read_bytes(), fixture.EDIT)

    def test_readonly_file_can_be_unlinked_in_writable_parent(self):
        self.target.chmod(0o444)
        result = self.local_child("delete")
        self.assertTrue(result["operation_succeeded"])
        self.assertFalse(self.target.exists())

    def test_replacement_has_new_inode_and_expected_content(self):
        before = fixture.snapshot(self.target)
        result = self.local_child("replace")
        self.assertTrue(result["operation_succeeded"])
        self.assertTrue(fixture.effect_observed("replace", before, fixture.snapshot(self.target)))

    def test_inherited_writable_fd_survives_path_mode_restriction(self):
        descriptor = os.open(self.target, os.O_WRONLY | os.O_APPEND | os.O_CLOEXEC)
        try:
            self.target.chmod(0o444)
            result = self.local_child("fd_append", descriptor)
        finally:
            os.close(descriptor)
        self.assertTrue(result["operation_succeeded"])
        self.assertEqual(self.target.read_bytes(), fixture.BASE + fixture.APPEND)

    def test_workspace_control_writes_and_executes_python(self):
        result = self.local_child("workspace_control")
        self.assertTrue(result["operation_succeeded"])
        self.assertEqual(result["python_exit_code"], 0)
        self.assertEqual(self.target.read_bytes(), fixture.BASE)

    def test_success_message_without_effect_is_not_accepted(self):
        before = fixture.snapshot(self.target)
        self.assertEqual(fixture.classify("rewrite", before, before, self.result()),
                         "inconclusive_effect_or_error")

    def test_mutation_despite_error_is_not_mislabeled_as_denied(self):
        before = fixture.snapshot(self.target)
        self.target.write_bytes(fixture.EDIT)
        self.assertEqual(fixture.classify("rewrite", before, fixture.snapshot(self.target),
                                         self.result(False, errno.EIO)), "effect_observed_despite_error")

    def test_denial_requires_expected_errno_and_unchanged_target(self):
        before = fixture.snapshot(self.target)
        self.assertEqual(fixture.classify("rewrite", before, before, self.result(False, errno.EACCES)),
                         "permission_denial_observed")
        self.assertEqual(fixture.classify("rewrite", before, before, self.result(False, errno.ENOSPC)),
                         "inconclusive_effect_or_error")

    def test_privilege_and_unintended_handle_leaks_are_rejected(self):
        good = self.result()
        self.assertTrue(fixture.identity_valid(good))
        for change in ("capability", "root", "fd", "newprivs"):
            result = copy.deepcopy(good)
            if change == "capability":
                result["identity"]["status"]["CapEff"] = "2"
            elif change == "root":
                result["identity"]["uid"] = [0, 0, 0]
            elif change == "fd":
                result["identity"]["inherited_probe_fds"] = [{"fd": 4, "target": "/probe/log"}]
            else:
                result["identity"]["status"]["NoNewPrivs"] = "0"
            with self.subTest(change=change):
                self.assertFalse(fixture.identity_valid(result))
        good["identity"]["inherited_probe_fds"] = [{"fd": 4, "target": "/probe/log"}]
        self.assertTrue(fixture.identity_valid(good, descriptor_expected=True))

    def test_container_has_no_network_or_host_data_mounts(self):
        command = runner.container_command("sha256:synthetic", "probe-name", "synthetic-id")
        self.assertEqual(command[command.index("--network") + 1], "none")
        self.assertIn("--pull=never", command)
        self.assertIn("--read-only", command)
        self.assertNotIn("--privileged", command)
        self.assertNotIn("--mount", command)
        self.assertNotIn("--volume", command)
        self.assertEqual(command[-4:], ["python3", "sha256:synthetic", "-I", "-"])

    def test_cleanup_does_not_remove_unexpected_containers(self):
        with patch.object(runner, "command", return_value="other-container") as call:
            with self.assertRaisesRegex(ValueError, "Unexpected container"):
                runner.remove_own_container("expected", "id")
            self.assertEqual(call.call_count, 1)
        with patch.object(runner, "command", side_effect=["expected", "", ""]) as call:
            runner.remove_own_container("expected", "id")
            self.assertEqual(call.call_args_list[1].args[0], ["docker", "rm", "--force", "expected"])

    def test_inspection_rejects_extra_capabilities_or_host_mounts(self):
        record = {"network_mode": "none", "readonly_rootfs": True, "binds": None, "mounts": [],
                  "user": "0:0", "entrypoint": ["python3"], "command": ["-I", "-"],
                  "tmpfs": {"/probe": "rw"}, "cap_drop": ["ALL"],
                  "cap_add": ["CAP_CHOWN", "CAP_DAC_OVERRIDE", "CAP_SETUID", "CAP_SETGID"],
                  "security_options": ["no-new-privileges"]}
        runner.validate_inspection(record)
        changed = copy.deepcopy(record)
        changed["cap_add"].append("CAP_SYS_ADMIN")
        with self.assertRaisesRegex(ValueError, "capabilities"):
            runner.validate_inspection(changed)
        changed = copy.deepcopy(record)
        changed["mounts"] = [{"Type": "bind", "Source": "/home"}]
        with self.assertRaisesRegex(ValueError, "host bind"):
            runner.validate_inspection(changed)

    def test_diagnostic_export_is_idempotent_and_preserves_conflicting_file(self):
        destination = self.root / "download.json"
        runner.export_diagnostics(self.root, destination, {}, {}, {}, {})
        before = destination.read_bytes()
        runner.export_diagnostics(self.root, destination, {}, {}, {}, {})
        self.assertEqual(destination.read_bytes(), before)
        with self.assertRaisesRegex(ValueError, "different diagnostic"):
            runner.export_diagnostics(self.root, destination, {"changed": True}, {}, {}, {})
        self.assertEqual(destination.read_bytes(), before)


if __name__ == "__main__":
    unittest.main()
