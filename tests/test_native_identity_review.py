import base64
import copy
import io
import json
import unittest
from unittest.mock import patch
import zipfile

from research.native import native_identity_analysis as old
from research.native import review_native_identity as review

WARNING = "Model metadata for `gpt-6-sol` not found. Defaulting to fallback metadata; this can degrade performance and cause issues."


def stream():
    return [{"type": "thread.started", "thread_id": "session"},
            {"type": "item.completed", "item": {"id": "item_0", "type": "error", "message": WARNING}},
            {"type": "turn.started"},
            {"type": "item.completed", "item": {"id": "item_1", "type": "agent_message", "text": "MEMORY-token"}},
            {"type": "turn.completed", "usage": {}}]


def native_rows():
    return [{"type": "event_msg", "payload": {"type": "task_started"}},
            {"type": "response_item", "payload": {"type": "message", "role": "user",
                "content": [{"type": "input_text", "text": "Recall"}]}},
            {"type": "response_item", "payload": {"type": "message", "role": "assistant",
                "content": [{"type": "output_text", "text": "MEMORY-token"}]}},
            {"type": "event_msg", "payload": {"type": "task_complete"}}]


class NativeIdentityReviewTests(unittest.TestCase):
    def test_real_warning_shape_reproduces_old_false_positive(self):
        rows = stream()
        saved = copy.deepcopy(rows)
        self.assertTrue(old.resume_has_tool_activity(rows))
        result = review.review_resume_events(rows, "gpt-6-sol")
        self.assertFalse(result["tool_activity_detected"])
        self.assertTrue(result["no_tool_activity_verified"])
        self.assertEqual(len(result["retained_diagnostics"]), 1)
        self.assertEqual(result["retained_diagnostics"][0]["event"], rows[1])
        self.assertEqual(rows, saved)

    def test_real_tool_call_remains_detected_with_warning(self):
        for kind in review.TOOL_ITEMS:
            rows = stream()
            rows.insert(3, {"type": "item.started", "item": {"id": "call", "type": kind}})
            with self.subTest(kind=kind):
                result = review.review_resume_events(rows, "gpt-6-sol")
                self.assertTrue(result["tool_activity_detected"])
                self.assertFalse(result["no_tool_activity_verified"])

    def test_unknown_errors_never_become_no_tool_evidence(self):
        for message in ("Authentication failed", "Tool execution failed", WARNING + " extra", WARNING.replace("gpt-6-sol", "other")):
            rows = stream(); rows[1]["item"]["message"] = message
            with self.subTest(message=message):
                result = review.review_resume_events(rows, "gpt-6-sol")
                self.assertIsNone(result["tool_activity_detected"])
                self.assertFalse(result["no_tool_activity_verified"])

    def test_warning_cannot_hide_an_additional_command_field(self):
        rows = stream(); rows[1]["item"]["command"] = "echo tool"
        self.assertFalse(review.review_resume_events(rows, "gpt-6-sol")["no_tool_activity_verified"])

    def test_diagnostic_after_turn_start_is_not_silently_ignored(self):
        rows = stream(); rows[1], rows[2] = rows[2], rows[1]
        self.assertFalse(review.review_resume_events(rows, "gpt-6-sol")["no_tool_activity_verified"])

    def test_unknown_item_and_unknown_top_level_records_block_readiness(self):
        cases = [{"type": "item.completed", "item": {"type": "new_tool"}},
                 {"type": "unknown_record"}, {"type": "error", "message": WARNING}]
        for event in cases:
            rows = stream(); rows.insert(3, event)
            self.assertFalse(review.review_resume_events(rows, "gpt-6-sol")["no_tool_activity_verified"])

    def test_passive_message_with_tool_field_is_not_accepted(self):
        rows = stream(); rows[3]["item"]["tool_calls"] = [{"name": "shell"}]
        self.assertFalse(review.review_resume_events(rows, "gpt-6-sol")["no_tool_activity_verified"])

    def test_missing_or_failed_turn_is_not_no_tool_success(self):
        for rows in ([], stream()[:-1], stream() + [{"type": "turn.failed"}]):
            self.assertFalse(review.review_resume_events(rows, "gpt-6-sol")["no_tool_activity_verified"])

    def test_native_history_corroborates_messages_and_rejects_tool_records(self):
        rows = native_rows()
        self.assertTrue(review.native_resume_review(rows)["no_tool_activity_verified"])
        for event in [{"type": "response_item", "payload": {"type": "function_call", "name": "shell"}},
                      {"type": "event_msg", "payload": {"type": "exec_command_begin"}},
                      {"type": "response_item", "payload": {"type": "custom_tool_call"}},
                      {"type": "unrecognized", "payload": {}}]:
            self.assertFalse(review.native_resume_review(rows + [event])["no_tool_activity_verified"])

    def test_native_message_with_tools_or_tool_role_is_not_passive(self):
        for field, value in (("role", "tool"), ("tool_calls", ["shell"]), ("recipient", "functions")):
            rows = native_rows(); rows[2]["payload"][field] = value
            self.assertFalse(review.native_resume_review(rows)["no_tool_activity_verified"])

    def test_usage_metadata_is_not_a_tool_call(self):
        rows = native_rows() + [{"type": "event_msg", "payload": {"type": "token_count", "rate_limits": {"private": "retained"}}}]
        result = review.native_resume_review(rows)
        self.assertTrue(result["no_tool_activity_verified"])
        self.assertNotIn("retained", json.dumps(result))

    def test_clock_adjustment_retained_without_performance_claim(self):
        values = [{"observed_ns": 2_000_000_000, "monotonic_ns": 1_000_000_000},
                  {"observed_ns": 1_300_000_000, "monotonic_ns": 1_100_000_000}]
        result = review.clock_review(values)
        self.assertTrue(result["monotonic_order_preserved"])
        self.assertFalse(result["performance_claim_supported"])
        self.assertEqual(result["clock_changes"][0]["offset_change_ns"], -800_000_000)
        values[1]["monotonic_ns"] = 900_000_000
        self.assertFalse(review.clock_review(values)["monotonic_order_preserved"])

    def test_transport_requires_matching_pid_success_and_drained_output(self):
        stage = {"name": "resume", "pid": 10, "supervisor_pid": 9, "exit_code": 0}
        rows = [{"kind": "started", "pid": 10, "supervisor_pid": 9},
                {"kind": "stdout", "data_b64": base64.b64encode(b"original bytes\n").decode()},
                {"kind": "exited", "pid": 10, "returncode": 0, "signal": None, "output_drained": True}]
        def files(values):return {"process-resume.jsonl": b"\n".join(json.dumps(v).encode() for v in values)}
        self.assertEqual(review.decode_stage(files(rows), "", stage), (b"original bytes\n", b""))
        for key, value in (("pid", 11), ("returncode", 1), ("output_drained", False)):
            altered = copy.deepcopy(rows); altered[-1][key] = value
            with self.assertRaises(RuntimeError):review.decode_stage(files(altered), "", stage)

    def test_archive_hash_guard_rejects_other_bytes(self):
        with self.assertRaisesRegex(RuntimeError, "archive differs"):
            review.verify_archive(b"not the saved archive")

    def test_archive_membership_and_hashes_are_verified(self):
        def archive(extra=False, incorrect=False):
            data = b"evidence"
            manifest = {"files": {"raw": {"sha256": "0" * 64 if incorrect else review.sha(data), "bytes": len(data)}}}
            buffer = io.BytesIO()
            with zipfile.ZipFile(buffer, "w") as package:
                package.writestr("review-manifest.json", json.dumps(manifest))
                package.writestr("raw", data)
                if extra:package.writestr("extra", b"unlisted")
            return buffer.getvalue()
        good = archive()
        with patch.object(review, "ARCHIVE_SHA", review.sha(good)):
            self.assertEqual(review.verify_archive(good), {"raw": b"evidence"})
        for bad in (archive(extra=True), archive(incorrect=True)):
            with patch.object(review, "ARCHIVE_SHA", review.sha(bad)), self.assertRaises(RuntimeError):
                review.verify_archive(bad)


if __name__ == "__main__":
    unittest.main()
