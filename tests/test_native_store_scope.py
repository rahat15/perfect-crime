import base64
import copy
import hashlib
import json
from pathlib import Path
import sqlite3
import tempfile
import unittest
from unittest.mock import patch

from research.native import native_store_fixture as fixture
from research.native import run_native_store_scope as runner


def case(found):
    methods = ["initialize", "thread/read", "thread/turns/list", "thread/items/list"]
    replies = [{"result": {}}, {"result": {"thread": {"id": fixture.SESSION, "historyMode": "paginated"}}},
               {"result": {"data": [], "nextCursor": None}}, {"result": {"data": [], "nextCursor": None}}]
    if not found:
        replies[1:] = [{"error": {"code": -32600, "message": "thread not loaded: " + fixture.SESSION}} for _ in range(3)]
    return {"rpc": {"requests": [{"method": m, "response": r} for m, r in zip(methods, replies)],
                    "errors": [], "process_exit_code": 0, "forced_stop": False},
            "seed_sha256_before": fixture.SEED_SHA if found else None,
            "seed_sha256_after": fixture.SEED_SHA if found else None,
            "databases": [{"name": n, "tables": [{"name": t} for t in tables], "errors": [],
                           "quick_check": ["ok"], "database_unchanged_by_inspection": True}
                          for n, tables in (("state_5.sqlite", ["threads"]),
                                            ("thread_history_1.sqlite", ["thread_items", "thread_turns", "thread_history_projection_state"]))]}


def valid():
    return {"cases": {"empty_home": case(False), "copied_jsonl_only": case(True)}, "errors": []}


class AssessmentTests(unittest.TestCase):
    def test_zero_items_are_an_observation_not_a_failure(self):
        self.assertTrue(runner.assess(valid())["complete"])

    def test_nonzero_items_are_retained_without_forcing_expected_zero(self):
        data = valid()
        data["cases"]["copied_jsonl_only"]["rpc"]["requests"][3]["response"]["result"]["data"] = [{"id": "retained"}]
        original = copy.deepcopy(data)
        self.assertTrue(runner.assess(data)["complete"])
        self.assertEqual(data, original)

    def test_empty_home_finding_session_blocks_completion(self):
        data = valid(); data["cases"]["empty_home"] = case(True)
        self.assertFalse(runner.assess(data)["complete"])

    def test_arbitrary_negative_control_error_is_not_missing_session(self):
        data = valid(); data["cases"]["empty_home"]["rpc"]["requests"][1]["response"] = {"error": {"code": -32600, "message": "authentication failed"}}
        self.assertFalse(runner.assess(data)["complete"])

    def test_seed_change_blocks_completion(self):
        data = valid(); data["cases"]["copied_jsonl_only"]["seed_sha256_after"] = "changed"
        self.assertFalse(runner.assess(data)["complete"])

    def test_missing_original_schema_blocks_completion(self):
        data = valid(); data["cases"]["copied_jsonl_only"]["databases"] = []
        self.assertFalse(runner.assess(data)["complete"])

    def test_missing_response_and_partial_pagination_block_completion(self):
        for value in ({"error": {"code": -1}}, {"result": {"data": [], "nextCursor": "more"}}):
            with self.subTest(value=value):
                data = valid(); data["cases"]["copied_jsonl_only"]["rpc"]["requests"][3]["response"] = value
                self.assertFalse(runner.assess(data)["complete"])

    def test_execution_method_blocks_completion(self):
        data = valid(); data["cases"]["copied_jsonl_only"]["rpc"]["requests"][3]["method"] = "turn/start"
        self.assertFalse(runner.assess(data)["complete"])

    def test_transport_and_inspection_failures_block_completion(self):
        for key, value in (("forced_stop", True), ("process_exit_code", 1), ("errors", ["timeout"])):
            with self.subTest(key=key):
                data = valid(); data["cases"]["copied_jsonl_only"]["rpc"][key] = value
                self.assertFalse(runner.assess(data)["complete"])

    def test_missing_case_blocks_completion(self):
        data = valid(); del data["cases"]["empty_home"]
        self.assertFalse(runner.assess(data)["complete"])

    def test_database_change_blocks_completion(self):
        data = valid(); data["cases"]["copied_jsonl_only"]["databases"][0]["database_unchanged_by_inspection"] = False
        self.assertFalse(runner.assess(data)["complete"])

    def test_outcome_does_not_claim_native_resume_or_defense(self):
        result = runner.assess(valid())
        self.assertFalse(result["native_model_resume_tested"])
        self.assertFalse(result["native_defense_tested"])


class IsolationAndCaptureTests(unittest.TestCase):
    def test_no_host_mount_credentials_network_or_security_relaxation(self):
        args = runner.create_args("test", "owned", "print('fixture')")
        self.assertIn("--pull=never", args)
        self.assertIn("--network=none", args)
        self.assertIn("--read-only", args)
        self.assertIn("--user=1000:1000", args)
        self.assertIn("--cap-drop=ALL", args)
        self.assertIn("--security-opt=no-new-privileges", args)
        self.assertNotIn("--privileged", args)
        self.assertNotIn("--mount", args)
        self.assertNotIn("--volume", args)
        self.assertFalse(any("seccomp=unconfined" in s for s in args))

    def test_protocol_has_no_execution_or_resume_requests(self):
        self.assertEqual(fixture.METHODS, {"initialize", "thread/read", "thread/turns/list", "thread/items/list"})

    def test_active_or_unknown_messages_are_rejected_even_on_shutdown(self):
        for value in ({"method": "turn/started"}, {"id": 9, "method": "item/commandExecution/requestApproval"},
                      {"method": "unclassified"}, ["not an object"]):
            with self.subTest(value=value):
                with self.assertRaises(RuntimeError): fixture.validate_read_message(value)
        fixture.validate_read_message({"id": 2, "result": {}})
        fixture.validate_read_message({"method": "configWarning", "params": {"message": "retained"}})

    def test_disabled_remote_control_notice_is_passive_but_enabled_is_blocked(self):
        fixture.validate_read_message({"method": "remoteControl/status/changed", "params": {"status": "disabled"}})
        with self.assertRaises(RuntimeError):
            fixture.validate_read_message({"method": "remoteControl/status/changed", "params": {"status": "enabled"}})

    def test_credential_environment_is_not_inherited(self):
        with patch.dict("os.environ", {"OPENAI_API_KEY": "private", "GITHUB_TOKEN": "private"}):
            env = fixture.process_env(Path("/private-disposable-home"))
        self.assertNotIn("OPENAI_API_KEY", env)
        self.assertNotIn("GITHUB_TOKEN", env)

    def test_unexpected_or_wrong_seed_is_rejected(self):
        with self.assertRaises(RuntimeError): fixture.decode_seed({"seed_b64": "", "extra": True})
        with self.assertRaises(RuntimeError): fixture.decode_seed({"seed_b64": base64.b64encode(b"wrong").decode()})

    def test_sqlite_query_preserves_bytes_and_only_returns_counts(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            path = root / "thread_history_1.sqlite"
            db = sqlite3.connect(path)
            db.execute("CREATE TABLE thread_items(thread_id TEXT, item_json TEXT)")
            db.execute("INSERT INTO thread_items VALUES (?, ?)", (fixture.SESSION, "PRIVATE CONTENT"))
            db.commit(); db.close()
            before = path.read_bytes()
            rows = fixture.sqlite_inventory(root)
            self.assertEqual(path.read_bytes(), before)
            self.assertEqual(rows[0]["quick_check"], ["ok"])
            self.assertEqual(rows[0]["tables"][0]["copied_session_rows"], 1)
            self.assertNotIn("PRIVATE CONTENT", json.dumps(rows))

    def test_corrupt_database_is_reported(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory); (root / "broken.sqlite").write_bytes(b"not a database")
            result = fixture.sqlite_inventory(root)
            self.assertTrue(result[0]["errors"])
            self.assertTrue(result[0]["database_unchanged_by_inspection"])

    def test_database_symbolic_link_is_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory); target = root / "file"; target.write_bytes(b"x")
            (root / "linked.sqlite").symlink_to(target)
            with self.assertRaises(RuntimeError): fixture.sqlite_inventory(root)


if __name__ == "__main__":
    unittest.main()
