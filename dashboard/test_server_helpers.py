"""Focused regression tests for dashboard request helpers."""
import json
import os
import sys
import tempfile
import time
import unittest
from pathlib import Path

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import server
from server import _normalize_extra_points


class NormalizeExtraPointsTest(unittest.TestCase):
    def test_trims_dedupes_and_skips_non_strings(self):
        self.assertEqual(
            _normalize_extra_points(["  我的判断  ", "", None, 7, "我的判断", "第二条"]),
            ["我的判断", "第二条"],
        )

    def test_limits_count(self):
        points = [f"观点{i}" for i in range(30)]
        self.assertEqual(len(_normalize_extra_points(points)), 20)
        self.assertEqual(_normalize_extra_points(points)[-1], "观点19")

    def test_limits_each_point_length(self):
        result = _normalize_extra_points(["x" * 700])
        self.assertEqual(len(result[0]), 500)

    def test_requires_array(self):
        with self.assertRaisesRegex(ValueError, "must be an array"):
            _normalize_extra_points("not-an-array")


class PendingApprovalsTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.old_file = server._PENDING_APPROVALS_FILE
        self.old_ttl = server.PENDING_APPROVAL_TTL_DAYS
        self.old_pending = dict(server._pending_approvals)
        server._PENDING_APPROVALS_FILE = str(Path(self.tmp.name) / "pending.json")
        server.PENDING_APPROVAL_TTL_DAYS = 3
        server._pending_approvals.clear()

    def tearDown(self):
        server._pending_approvals.clear()
        server._pending_approvals.update(self.old_pending)
        server._PENDING_APPROVALS_FILE = self.old_file
        server.PENDING_APPROVAL_TTL_DAYS = self.old_ttl
        self.tmp.cleanup()

    def test_prunes_topics_older_than_ttl(self):
        now = time.time()
        server._pending_approvals.update({
            "old": {"topic": "old", "added_at": now - 4 * 86400},
            "fresh": {"topic": "fresh", "added_at": now - 3600},
        })
        removed = server._prune_pending_approvals()
        self.assertEqual(removed, 1)
        self.assertNotIn("old", server._pending_approvals)
        self.assertIn("fresh", server._pending_approvals)

    def test_save_and_load_round_trip(self):
        now = time.time()
        server._pending_approvals["topic"] = {
            "topic": "topic", "write_value": 9, "hot_score": 88,
            "added_at": now, "expires_at": now + 3 * 86400,
        }
        server._save_pending_approvals()
        self.assertTrue(Path(server._PENDING_APPROVALS_FILE).exists())
        server._pending_approvals.clear()
        server._load_pending_approvals()
        self.assertEqual(server._pending_approvals["topic"]["write_value"], 9)

    def test_payload_has_age_and_expiry(self):
        now = time.time()
        server._pending_approvals["topic"] = {
            "topic": "topic", "write_value": 8, "hot_score": 70,
            "added_at": now - 7200, "expires_at": now + 3600,
        }
        payload = server._pending_approvals_payload()
        self.assertEqual(payload["count"], 1)
        self.assertEqual(payload["ttl_days"], 3)
        self.assertAlmostEqual(payload["items"][0]["age_hours"], 2, delta=0.1)
        self.assertAlmostEqual(payload["items"][0]["expires_in_hours"], 1, delta=0.1)

    def test_legacy_added_time_is_supported(self):
        server._pending_approvals["legacy"] = {
            "topic": "legacy", "added_time": time.strftime("%Y-%m-%d %H:%M"),
        }
        payload = server._pending_approvals_payload()
        self.assertEqual(payload["count"], 1)
        self.assertIn("added_at", payload["items"][0])


if __name__ == "__main__":
    unittest.main()
