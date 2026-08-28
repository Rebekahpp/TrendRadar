"""Focused regression tests for dashboard request helpers."""
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
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


if __name__ == "__main__":
    unittest.main()
