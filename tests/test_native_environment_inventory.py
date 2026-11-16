"""Isolation and retention checks; these do not emulate native Codex behavior."""
import copy
import json
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import Mock, patch

from research.native import inspect_environment as env


def container_info(token="token"):
    return {"Image": env.IMAGE,
            "Config": {"User": "1000:1000", "Labels": {env.LABEL: token},
                       "Env": ["HOME=/home/agent"]},
            "HostConfig": {"NetworkMode": "none", "ReadonlyRootfs": True,
                           "Privileged": False, "CapDrop": ["ALL"],
                           "SecurityOpt": ["no-new-privileges"]},
            "Mounts": [],
            "State": {"Status": "exited", "ExitCode": 0, "OOMKilled": False}}


class EnvironmentInventoryTests(unittest.TestCase):
    def test_queries_never_request_model_or_authentication(self):
        for name, command in env.HELP_COMMANDS:
            with self.subTest(name=name):
                self.assertEqual(command[0], "codex")
                self.assertIn(command[-1], ("--version", "--help"))
                self.assertNotIn("login", command)

    def test_container_is_pinned_and_has_no_mounts_or_network(self):
        command = env.create_command("test-container", "token")
        self.assertIn(env.IMAGE, command)
        for flag in ("--pull=never", "--network=none", "--read-only",
                     "--cap-drop=ALL", "--user=1000:1000"):
            self.assertIn(flag, command)
        self.assertNotIn("--mount", command)
        self.assertNotIn("--volume", command)
        self.assertEqual(command[-3:], [env.IMAGE, "-", "--inside"])
        env.validate_container(container_info(), "token")

    def test_unexpected_privilege_or_access_prevents_start(self):
        changes = [("Config", "User", "0:0"),
                   ("Config", "Env", ["OPENAI_API_KEY=synthetic-test-value"]),
                   ("HostConfig", "NetworkMode", "host"),
                   ("HostConfig", "ReadonlyRootfs", False),
                   ("HostConfig", "Privileged", True),
                   ("HostConfig", "CapAdd", ["SYS_ADMIN"]),
                   ("HostConfig", "CapDrop", []),
                   ("HostConfig", "SecurityOpt", []),
                   ("HostConfig", "Binds", ["/home/test:/data"]),
                   ("HostConfig", "Devices", [{"PathOnHost": "/dev/example"}])]
        for section, key, value in changes:
            with self.subTest(key=key):
                info = container_info()
                info[section][key] = value
                with self.assertRaises(RuntimeError):
                    env.validate_container(info, "token")
        info = container_info()
        info["Mounts"] = [{"Type": "volume"}]
        with self.assertRaises(RuntimeError):
            env.validate_container(info, "token")

    def test_other_containers_are_not_accepted(self):
        info = container_info()
        with self.assertRaises(RuntimeError):
            env.validate_container(info, "different-token")
        info["Image"] = "different-image"
        with self.assertRaises(RuntimeError):
            env.validate_container(info, "token")

    def test_unsupported_help_is_retained_as_data(self):
        process = Mock(returncode=2)
        process.communicate.return_value = ("", "unknown subcommand")
        with patch.object(env.subprocess, "Popen", return_value=process):
            result = env.capture_help("unsupported", ["codex", "example", "--help"])
        self.assertEqual(result["exit_code"], 2)
        self.assertFalse(result["timed_out"])
        self.assertEqual(result["stderr"], "unknown subcommand")

    def test_timeout_stops_the_help_process_group(self):
        process = Mock(returncode=-9, pid=123)
        process.communicate.side_effect = [subprocess.TimeoutExpired("help", 12),
                                           ("partial", "")]
        with patch.object(env.subprocess, "Popen", return_value=process), \
                patch.object(env.os, "killpg") as kill:
            result = env.capture_help("slow", ["codex", "--help"])
        kill.assert_called_once_with(123, env.signal.SIGKILL)
        self.assertTrue(result["timed_out"])
        self.assertEqual(result["stdout"], "partial")

    def fake_docker(self, fail=False):
        calls = []
        removed = False
        token = None
        def run(command, **kwargs):
            nonlocal removed, token
            calls.append(command)
            if command[:3] == ["docker", "image", "inspect"]:
                return json.dumps([{"Id": env.IMAGE, "Os": "linux",
                                    "Architecture": "amd64", "Config": {}}])
            if command[:2] == ["docker", "create"]:
                token = command[command.index("--label") + 1].split("=", 1)[1]
                return "container-id\n"
            if command[:2] == ["docker", "inspect"]:
                return json.dumps([container_info(token)])
            if command[:2] == ["docker", "start"]:
                if fail:
                    raise subprocess.TimeoutExpired("docker start", 120)
                return json.dumps({"commands": [
                    {"name": name, "argv": argv, "exit_code": 0,
                     "stdout": env.EXPECTED_VERSION if name == "version" else "Help",
                     "stderr": "", "timed_out": False, "output_truncated": False}
                    for name, argv in env.HELP_COMMANDS]})
            if command[:2] == ["docker", "ps"]:
                self.assertIn(f"label={env.LABEL}={token}", command)
                return "" if removed else "container-id\n"
            if command[:2] == ["docker", "rm"]:
                self.assertEqual(command[-1], "container-id")
                removed = True
                return "container-id\n"
            self.fail(f"Unexpected command: {command}")
        return run, calls

    def test_completed_inventory_is_reexported_without_rerunning(self):
        run, calls = self.fake_docker()
        with tempfile.TemporaryDirectory() as temporary, \
                patch.object(env, "ROOT", Path(temporary)), \
                patch.object(env, "run", side_effect=run):
            first = env.collect()
            count = len(calls)
            second = env.collect()
        self.assertTrue(first["inventory_complete"])
        self.assertTrue(first["container_removed"])
        self.assertEqual(first, second)
        self.assertEqual(len(calls), count)

    def test_failure_is_retained_and_only_own_container_removed(self):
        run, calls = self.fake_docker(fail=True)
        with tempfile.TemporaryDirectory() as temporary, \
                patch.object(env, "ROOT", Path(temporary)), \
                patch.object(env, "run", side_effect=run):
            result = env.collect()
            saved = json.loads((Path(temporary) / env.OUTPUT / "environment.json").read_text())
            self.assertEqual(result, saved)
        self.assertFalse(result["inventory_complete"])
        self.assertTrue(result["errors"])
        self.assertTrue(result["container_removed"])


if __name__ == "__main__":
    unittest.main()
