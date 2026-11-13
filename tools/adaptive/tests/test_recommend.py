import json
import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import recommend  # noqa: E402


def pattern(pid, template, count, size, protected=0):
    return {"id": pid, "template": template, "count": count, "bytes": size,
            "kept": count, "dropped": 0, "bytes_dropped": 0, "protected": protected,
            "first_seen": 0, "last_seen": 0, "policy_drop_rate": None}


REPORT = {"version": 1, "patterns": [
    pattern("aa", "GET <*> took <NUM>ms", 10000, 500000),
    pattern("bb", "cache hit key=<*>", 5000, 200000),
    pattern("cc", "payment failed for <*>", 100, 9000, protected=100),
    pattern("dd", "user <*> logged in", 300, 9000),
    pattern("ee", "config reloaded", 2, 30),
    pattern("ff", "slow query <*>", 1000, 80000),
]}


class RecommendTest(unittest.TestCase):
    def rules(self, usage, **kwargs):
        policy, rows = recommend.recommend(REPORT, usage, **kwargs)
        return {rule["template"]: rule["drop_rate"] for rule in policy["patterns"]}, rows

    def test_read_ratio_buckets(self):
        rules, _ = self.rules({"GET <*> took <NUM>ms": 0, "bb": 20,
                               "user <*> logged in": 60, "slow query <*>": 900})
        self.assertEqual(rules["GET <*> took <NUM>ms"], 0.90)   # never
        self.assertEqual(rules["cache hit key=<*>"], 0.50)      # 0.4%, by id
        self.assertEqual(rules["user <*> logged in"], 0.10)     # 20%
        self.assertEqual(rules["slow query <*>"], 0.0)          # 90%, exempt

    def test_protected_and_small_patterns_get_no_rule(self):
        rules, rows = self.rules({})
        self.assertNotIn("payment failed for <*>", rules)
        self.assertNotIn("config reloaded", rules)
        reasons = {row["template"]: row["reason"] for row in rows}
        self.assertEqual(reasons["payment failed for <*>"], "protected")
        self.assertEqual(reasons["config reloaded"], "below min share")

    def test_listed_small_pattern_gets_a_rule(self):
        rules, _ = self.rules({"config reloaded": 2})
        self.assertEqual(rules["config reloaded"], 0.0)

    def test_unlisted_patterns_default_to_never(self):
        rules, rows = self.rules({}, never=0.75)
        self.assertEqual(rules["GET <*> took <NUM>ms"], 0.75)
        saved = {row["template"]: row["saved_bytes"] for row in rows}
        self.assertEqual(saved["GET <*> took <NUM>ms"], 375000)

    def test_cli_writes_a_loadable_policy(self):
        with tempfile.TemporaryDirectory() as directory:
            report = os.path.join(directory, "report.json")
            usage = os.path.join(directory, "usage.json")
            out = os.path.join(directory, "policy.json")
            with open(report, "w", encoding="utf-8") as stream:
                json.dump(REPORT, stream)
            with open(usage, "w", encoding="utf-8") as stream:
                json.dump({"slow query <*>": 1000}, stream)

            self.assertEqual(recommend.main(["--report", report, "--usage", usage,
                                             "--out", out]), 0)
            with open(out, encoding="utf-8") as stream:
                policy = json.load(stream)

            self.assertEqual(policy["version"], 1)
            for rule in policy["patterns"]:
                self.assertIn("template", rule)
                self.assertGreaterEqual(rule["drop_rate"], 0.0)
                self.assertLessEqual(rule["drop_rate"], 1.0)
            self.assertEqual([name for name in os.listdir(directory)
                              if name.startswith(".policy-")], [])

    def test_rules_carry_the_group_of_their_pattern(self):
        report = {"patterns": [
            {"id": "aa", "group": "payments", "template": "ping", "count": 1000,
             "bytes": 9000, "protected": 0},
            {"id": "aa", "group": "", "template": "ping", "count": 1000,
             "bytes": 9000, "protected": 0},
        ]}
        policy, _ = recommend.recommend(report, {})
        self.assertEqual(policy["patterns"], [
            {"template": "ping", "drop_rate": 0.9, "group": "payments"},
            {"template": "ping", "drop_rate": 0.9},
        ])

    def test_empty_report(self):
        policy, rows = recommend.recommend({"patterns": []}, {})
        self.assertEqual(policy, {"version": 1, "patterns": []})
        self.assertEqual(rows, [])


if __name__ == "__main__":
    unittest.main()
