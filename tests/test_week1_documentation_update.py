"""Documentation migration and tracked-deletion checks with local fixtures only."""

from contextlib import ExitStack, redirect_stdout
import io
import json
from pathlib import Path
import subprocess
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch
import zipfile

from research.tools import install_week1_final as update
from research.tools import pause_checkpoint as checkpoint
from research.tools import build_pilot_review as pilot


class DocumentationUpdateTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.name = "research/README.md"
        self.retired = update.RETIRED[0]
        self.save(self.name, b"old documentation")
        self.save(self.retired, b"old communication template")
        self.save("host_lab/fixture.py", b"frozen experiment bytes")
        self.save("runs/baseline-financial-full-01/plan.json", json.dumps({
            "source_sha256": {"host_lab/fixture.py": update.digest(b"frozen experiment bytes")}
        }).encode())
        self.archive = self.root / "update.zip"
        with zipfile.ZipFile(self.archive, "w") as package:
            package.writestr(self.name, "new technical documentation")
        self.digest = update.digest(self.archive.read_bytes())
        self.prior = {self.name: [update.digest(b"old documentation")],
                      self.retired: [update.digest(b"old communication template")],
                      update.RETIRED[1]: [update.digest(b"unused") ]}

    def save(self, name, content):
        path = self.root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(content)

    def install(self):
        with ExitStack() as stack:
            stack.enter_context(patch.object(update, "FILES", (self.name,)))
            stack.enter_context(patch.object(update, "PRIOR", self.prior))
            stack.enter_context(patch.object(update.Path, "cwd", return_value=self.root))
            stack.enter_context(patch.object(update.subprocess, "check_output", return_value="reproduce-financial\n"))
            stack.enter_context(redirect_stdout(io.StringIO()))
            return update.install(self.root, self.archive, self.digest)

    def test_known_previous_files_are_backed_up_and_template_removed(self):
        backup = self.install()
        self.assertEqual((backup / self.name).read_bytes(), b"old documentation")
        self.assertEqual((backup / self.retired).read_bytes(), b"old communication template")
        self.assertFalse((self.root / self.retired).exists())
        self.assertEqual((self.root / self.name).read_bytes(), b"new technical documentation")
        self.assertEqual((self.root / "host_lab/fixture.py").read_bytes(), b"frozen experiment bytes")
        self.install()  # An identical reinstall does not recreate retired files.

    def test_modified_template_is_preserved_before_any_replacement(self):
        self.save(self.retired, b"reviewer-added work")
        with self.assertRaisesRegex(ValueError, "unrecognized changes"):
            self.install()
        self.assertEqual((self.root / self.name).read_bytes(), b"old documentation")
        self.assertEqual((self.root / self.retired).read_bytes(), b"reviewer-added work")

    def test_original_handoff_manifest_is_archived_before_regeneration(self):
        manifest = {"schema": "initial-replication-handoff-v1",
                    "public_file_sha256": {self.name: update.digest(b"old documentation")}}
        original = json.dumps(manifest).encode()
        self.save(update.MANIFEST, original)
        backup = self.install()
        self.assertEqual((backup / update.MANIFEST).read_bytes(), original)
        self.assertFalse((self.root / update.MANIFEST).exists())

    def test_frozen_source_change_blocks_document_update(self):
        self.save("host_lab/fixture.py", b"changed")
        with self.assertRaisesRegex(ValueError, "Frozen experiment source changed"):
            self.install()
        self.assertEqual((self.root / self.name).read_bytes(), b"old documentation")

    def test_pilot_builder_no_longer_generates_a_reply_template(self):
        self.assertFalse(hasattr(pilot, "TEMPLATE"))
        self.assertNotIn("Reply with your assessment", pilot.README)
        self.assertFalse(set(checkpoint.PUBLIC) & set(checkpoint.RETIRED))


class LocalPublicationTests(unittest.TestCase):
    def test_publication_removes_tracked_template_and_keeps_unrelated_file(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "repo"
            remote = Path(temporary) / "remote.git"
            root.mkdir()
            def local_git(*args, check=True):
                return subprocess.run(["git", "-C", str(root), *args], text=True,
                                      capture_output=True, check=check)
            subprocess.run(["git", "init", "--bare", str(remote)], capture_output=True, check=True)
            local_git("init", "-b", checkpoint.BRANCH)
            local_git("config", "user.name", "Synthetic Test")
            local_git("config", "user.email", "synthetic@example.invalid")
            path = root / checkpoint.RETIRED[0]
            path.parent.mkdir(parents=True)
            path.write_text("synthetic old template")
            (root / "unrelated.txt").write_text("keep this")
            local_git("add", ".")
            local_git("commit", "-m", "Synthetic initial state")
            local_git("remote", "add", "origin", str(remote))
            old_head = local_git("rev-parse", "HEAD").stdout.strip()
            path.unlink()
            readme = root / "research/README.md"
            readme.write_text("synthetic technical documentation")
            archive = Path(temporary) / "backup.tar.gz"
            archive.write_bytes(b"synthetic archive placeholder")
            checkpoint.save_json(root / checkpoint.STATE, {
                "backup_verified": True, "backup_archive": str(archive),
                "prepared_head": old_head, "public_files": ["research/README.md"],
                "public_sha256": {"research/README.md": checkpoint.sha256(readme)},
                "retired_tracked_files": [checkpoint.RETIRED[0]],
            })
            def local_run(*args, **kwargs):
                if args[:3] == ("gh", "api", "user"):
                    return SimpleNamespace(stdout=json.dumps({"login": "test", "id": 1}))
                if args[:2] == ("gh", "api"):
                    return SimpleNamespace(stdout=json.dumps({"permissions": {"push": True}}))
                if args[0] != "git":
                    raise AssertionError("Unexpected external command")
                return local_git(*args[1:])
            with patch.object(checkpoint, "git", side_effect=local_git), \
                 patch.object(checkpoint, "run", side_effect=local_run), redirect_stdout(io.StringIO()):
                checkpoint.publish(root)
            head = local_git("rev-parse", "HEAD").stdout.strip()
            self.assertNotEqual(head, old_head)
            self.assertEqual(local_git("ls-tree", "-r", "--name-only", "HEAD", "--", *checkpoint.RETIRED).stdout, "")
            self.assertEqual((root / "unrelated.txt").read_text(), "keep this")
            self.assertEqual(local_git("show", old_head + ":" + checkpoint.RETIRED[0]).stdout,
                             "synthetic old template")
            self.assertEqual(local_git("ls-remote", "origin", "refs/heads/" + checkpoint.BRANCH).stdout.split()[0], head)


if __name__ == "__main__":
    unittest.main()
