import base64
from contextlib import redirect_stdout
import io
import json
import os
from pathlib import Path
import tempfile
import unittest

from research.native import native_identity_capture as capture
from research.native import native_identity_fixture as fixture


class NativeIdentityCaptureTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.home = self.root / "home"
        self.workspace = self.root / "workspace"
        (self.home / ".codex/sessions/2026").mkdir(parents=True)
        self.workspace.mkdir()
        self.session = "12345678-abcd-0000-1111-123456789012"
        self.path = self.home / ".codex/sessions/2026" / ("rollout-" + self.session + ".jsonl")
        self.path.write_bytes(b'{"message":"retained"}\n')

    def test_capture_is_exact_and_does_not_read_authentication(self):
        auth = self.home / ".codex/auth.json"
        auth.write_text("not even valid JSON: credential marker")
        result = capture.capture(self.session, self.home, self.workspace)
        self.assertEqual(base64.b64decode(result["traces"][0]["content_b64"]), self.path.read_bytes())
        self.assertNotIn("credential marker", json.dumps(result))
        self.assertFalse(any(r["path"].endswith("auth.json") for r in result["entries"]))

    def test_other_session_contents_are_not_exported(self):
        other = self.path.parent / "rollout-other-session.jsonl"
        other.write_text("unrelated conversation")
        self.assertNotIn("unrelated conversation", json.dumps(capture.capture(self.session, self.home, self.workspace)))

    def test_file_and_parent_symlinks_rejected(self):
        link = self.root / "link"
        link.symlink_to(self.path)
        with self.assertRaises(OSError):
            capture.read_regular(link, 100)
        parent = self.root / "parent"
        parent.symlink_to(self.path.parent, target_is_directory=True)
        with self.assertRaises(OSError):
            capture.read_regular(parent / self.path.name, 100)

    def test_fifo_and_size_limit_rejected(self):
        fifo = self.root / "fifo"
        os.mkfifo(fifo)
        with self.assertRaises(RuntimeError):
            capture.read_regular(fifo, 100)
        with self.assertRaises(RuntimeError):
            capture.read_regular(self.path, 2)

    def test_relative_or_parent_traversal_rejected(self):
        for path in (Path("relative"), self.root / ".." / "outside"):
            with self.assertRaises(ValueError):
                capture.read_regular(path, 100)

    def test_held_control_is_real_metadata_and_never_replaces_output(self):
        with redirect_stdout(io.StringIO()):
            result = fixture.run(self.workspace, seconds=0)
        self.assertEqual(result["entry"]["pid"], os.getpid())
        self.assertEqual(result["entry"]["pid_namespace"], os.readlink("/proc/self/ns/pid"))
        self.assertNotIn("argv", result["entry"])
        self.assertNotIn("environment", result["entry"])
        output = self.workspace / "native-identity-control.json"
        before = output.read_bytes()
        with self.assertRaises(RuntimeError):
            fixture.run(self.workspace, seconds=0)
        self.assertEqual(output.read_bytes(), before)


if __name__ == "__main__":
    unittest.main()
