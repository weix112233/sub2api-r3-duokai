import importlib.util
import unittest
from pathlib import Path


MODULE_PATH = Path(__file__).resolve().parent / "ttft_scheduler_replay.py"
SPEC = importlib.util.spec_from_file_location("ttft_scheduler_replay", MODULE_PATH)
MODULE = importlib.util.module_from_spec(SPEC)
assert SPEC and SPEC.loader
SPEC.loader.exec_module(MODULE)


def fixture():
    return {
        "schema": MODULE.SCHEMA,
        "sticky_weighted": False,
        "current_weights": {
            "priority": 1.0,
            "load": 1.0,
            "queue": 0.7,
            "error_rate": 0.8,
            "ttft": 0.5,
            "reset": 0.0,
            "quota_headroom": 0.0,
            "upstream_cost": 0.0,
            "previous_response": 5.0,
            "session_sticky": 3.0,
        },
        "candidate_weights": {
            "priority": 1.0,
            "load": 1.0,
            "queue": 0.7,
            "error_rate": 0.8,
            "ttft": 2.0,
            "reset": 0.0,
            "quota_headroom": 0.0,
            "upstream_cost": 0.0,
            "previous_response": 5.0,
            "session_sticky": 3.0,
        },
        "accounts": [
            {
                "account_ref": "acct_fast",
                "priority": 10,
                "load_rate": 65,
                "waiting_count": 2,
                "error_rate": 0.05,
                "ttft_ms": 300,
            },
            {
                "account_ref": "acct_slow",
                "priority": 10,
                "load_rate": 20,
                "waiting_count": 0,
                "error_rate": 0.05,
                "ttft_ms": 4000,
            },
        ],
    }


class TTFTSchedulerReplayTest(unittest.TestCase):
    def test_candidate_weight_can_promote_lower_ttft_account(self):
        result = MODULE.replay(fixture())

        self.assertEqual(0, result["provider_calls"])
        self.assertEqual(0, result["mutations"])
        self.assertEqual("acct_slow", result["current"]["ranking"][0]["account_ref"])
        self.assertEqual("acct_fast", result["candidate"]["ranking"][0]["account_ref"])

    def test_missing_ttft_uses_neutral_factor(self):
        data = fixture()
        data["accounts"][1]["ttft_ms"] = None

        result = MODULE.replay(data)
        slow = next(item for item in result["candidate"]["ranking"] if item["account_ref"] == "acct_slow")

        self.assertEqual(0.5, slow["factors"]["ttft"])

    def test_rejects_secret_bearing_or_non_anonymous_input(self):
        data = fixture()
        data["accounts"][0]["token"] = "must-not-be-accepted"

        with self.assertRaises(MODULE.ReplayInputError):
            MODULE.replay(data)

        data = fixture()
        data["accounts"][0]["account_ref"] = "user@example.com"
        with self.assertRaises(MODULE.ReplayInputError):
            MODULE.replay(data)

    def test_rejects_duplicate_account_refs(self):
        data = fixture()
        data["accounts"][1]["account_ref"] = data["accounts"][0]["account_ref"]

        with self.assertRaises(MODULE.ReplayInputError):
            MODULE.replay(data)


if __name__ == "__main__":
    unittest.main()
