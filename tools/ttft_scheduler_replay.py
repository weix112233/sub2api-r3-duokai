#!/usr/bin/env python3
"""Offline comparison of Sub2API scheduler weights using anonymous metrics only."""

from __future__ import annotations

import argparse
import json
import math
import re
import sys
from pathlib import Path
from typing import Any


SCHEMA = "sub2api.scheduler-replay.v1"
RESULT_SCHEMA = "sub2api.scheduler-replay-result.v1"
ACCOUNT_REF_RE = re.compile(r"^acct_[A-Za-z0-9_-]{1,48}$")
WEIGHT_FIELDS = (
    "priority",
    "load",
    "queue",
    "error_rate",
    "ttft",
    "reset",
    "quota_headroom",
    "upstream_cost",
    "previous_response",
    "session_sticky",
)
ACCOUNT_FIELDS = {
    "account_ref",
    "priority",
    "load_rate",
    "waiting_count",
    "error_rate",
    "ttft_ms",
    "reset_remaining_seconds",
    "quota_headroom_factor",
    "upstream_cost_factor",
    "previous_response_match",
    "session_sticky_match",
}
TOP_LEVEL_FIELDS = {
    "schema",
    "sticky_weighted",
    "current_weights",
    "candidate_weights",
    "accounts",
}
SECRET_LIKE_KEYS = {
    "authorization",
    "body",
    "cookie",
    "credential",
    "email",
    "hostname",
    "installation_id",
    "ip",
    "key",
    "name",
    "password",
    "prompt",
    "proxy",
    "response",
    "secret",
    "session_id",
    "thread_id",
    "token",
    "url",
    "user_id",
}


class ReplayInputError(ValueError):
    pass


def clamp01(value: float) -> float:
    return max(0.0, min(1.0, value))


def require_number(value: Any, field: str, minimum: float | None = None, maximum: float | None = None) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise ReplayInputError(f"{field} must be a number")
    number = float(value)
    if not math.isfinite(number):
        raise ReplayInputError(f"{field} must be finite")
    if minimum is not None and number < minimum:
        raise ReplayInputError(f"{field} must be >= {minimum}")
    if maximum is not None and number > maximum:
        raise ReplayInputError(f"{field} must be <= {maximum}")
    return number


def reject_secret_like_keys(value: Any, location: str = "input") -> None:
    if isinstance(value, dict):
        for key, nested in value.items():
            normalized = str(key).strip().lower()
            if normalized in SECRET_LIKE_KEYS or any(part in normalized for part in ("secret", "password", "credential", "cookie")):
                raise ReplayInputError(f"{location} contains forbidden field: {key}")
            reject_secret_like_keys(nested, f"{location}.{key}")
    elif isinstance(value, list):
        for index, nested in enumerate(value):
            reject_secret_like_keys(nested, f"{location}[{index}]")


def validate_weights(raw: Any, label: str) -> dict[str, float]:
    if not isinstance(raw, dict):
        raise ReplayInputError(f"{label} must be an object")
    unknown = set(raw) - set(WEIGHT_FIELDS)
    missing = set(WEIGHT_FIELDS) - set(raw)
    if unknown:
        raise ReplayInputError(f"{label} contains unsupported fields: {sorted(unknown)}")
    if missing:
        raise ReplayInputError(f"{label} is missing fields: {sorted(missing)}")
    weights = {field: require_number(raw[field], f"{label}.{field}", 0.0) for field in WEIGHT_FIELDS}
    if sum(weights[field] for field in WEIGHT_FIELDS[:8]) <= 0:
        raise ReplayInputError(f"{label} base weights must not all be zero")
    return weights


def validate_account(raw: Any, index: int) -> dict[str, Any]:
    if not isinstance(raw, dict):
        raise ReplayInputError(f"accounts[{index}] must be an object")
    unknown = set(raw) - ACCOUNT_FIELDS
    if unknown:
        raise ReplayInputError(f"accounts[{index}] contains unsupported fields: {sorted(unknown)}")

    account_ref = raw.get("account_ref")
    if not isinstance(account_ref, str) or not ACCOUNT_REF_RE.fullmatch(account_ref):
        raise ReplayInputError(f"accounts[{index}].account_ref must match {ACCOUNT_REF_RE.pattern}")

    waiting_count = raw.get("waiting_count", 0)
    if isinstance(waiting_count, bool) or not isinstance(waiting_count, int) or waiting_count < 0:
        raise ReplayInputError(f"accounts[{index}].waiting_count must be a non-negative integer")

    ttft_raw = raw.get("ttft_ms")
    reset_raw = raw.get("reset_remaining_seconds")
    account = {
        "account_ref": account_ref,
        "priority": require_number(raw.get("priority", 0), f"accounts[{index}].priority"),
        "load_rate": require_number(raw.get("load_rate", 0), f"accounts[{index}].load_rate", 0.0, 100.0),
        "waiting_count": waiting_count,
        "error_rate": require_number(raw.get("error_rate", 0), f"accounts[{index}].error_rate", 0.0, 1.0),
        "ttft_ms": None if ttft_raw is None else require_number(ttft_raw, f"accounts[{index}].ttft_ms", 0.000001),
        "reset_remaining_seconds": None
        if reset_raw is None
        else require_number(reset_raw, f"accounts[{index}].reset_remaining_seconds", 0.0),
        "quota_headroom_factor": require_number(
            raw.get("quota_headroom_factor", 0),
            f"accounts[{index}].quota_headroom_factor",
            0.0,
            1.0,
        ),
        "upstream_cost_factor": require_number(
            raw.get("upstream_cost_factor", 0.5),
            f"accounts[{index}].upstream_cost_factor",
            0.0,
            1.0,
        ),
        "previous_response_match": raw.get("previous_response_match", False),
        "session_sticky_match": raw.get("session_sticky_match", False),
    }
    for field in ("previous_response_match", "session_sticky_match"):
        if not isinstance(account[field], bool):
            raise ReplayInputError(f"accounts[{index}].{field} must be boolean")
    return account


def validate_input(raw: Any) -> dict[str, Any]:
    if not isinstance(raw, dict):
        raise ReplayInputError("input must be an object")
    reject_secret_like_keys(raw)
    unknown = set(raw) - TOP_LEVEL_FIELDS
    if unknown:
        raise ReplayInputError(f"input contains unsupported fields: {sorted(unknown)}")
    if raw.get("schema") != SCHEMA:
        raise ReplayInputError(f"schema must be {SCHEMA}")
    sticky_weighted = raw.get("sticky_weighted", False)
    if not isinstance(sticky_weighted, bool):
        raise ReplayInputError("sticky_weighted must be boolean")

    accounts_raw = raw.get("accounts")
    if not isinstance(accounts_raw, list) or len(accounts_raw) < 2:
        raise ReplayInputError("accounts must contain at least two anonymous entries")
    accounts = [validate_account(account, index) for index, account in enumerate(accounts_raw)]
    refs = [account["account_ref"] for account in accounts]
    if len(refs) != len(set(refs)):
        raise ReplayInputError("account_ref values must be unique")

    return {
        "sticky_weighted": sticky_weighted,
        "current_weights": validate_weights(raw.get("current_weights"), "current_weights"),
        "candidate_weights": validate_weights(raw.get("candidate_weights"), "candidate_weights"),
        "accounts": accounts,
    }


def score_accounts(accounts: list[dict[str, Any]], weights: dict[str, float], sticky_weighted: bool) -> list[dict[str, Any]]:
    priorities = [account["priority"] for account in accounts]
    min_priority, max_priority = min(priorities), max(priorities)
    max_waiting = max(1, *(account["waiting_count"] for account in accounts))

    ttft_samples = [account["ttft_ms"] for account in accounts if account["ttft_ms"] is not None]
    min_ttft = min(ttft_samples) if ttft_samples else None
    max_ttft = max(ttft_samples) if ttft_samples else None

    reset_samples = [
        account["reset_remaining_seconds"]
        for account in accounts
        if account["reset_remaining_seconds"] is not None
    ]
    min_reset = min(reset_samples) if reset_samples else None
    max_reset = max(reset_samples) if reset_samples else None

    scored = []
    for account in accounts:
        priority_factor = 1.0
        if max_priority > min_priority:
            priority_factor = 1 - (account["priority"] - min_priority) / (max_priority - min_priority)
        load_factor = 1 - clamp01(account["load_rate"] / 100.0)
        queue_factor = 1 - clamp01(account["waiting_count"] / max_waiting)
        error_factor = 1 - clamp01(account["error_rate"])

        ttft_factor = 0.5
        if account["ttft_ms"] is not None and min_ttft is not None and max_ttft is not None and max_ttft > min_ttft:
            ttft_factor = 1 - clamp01((account["ttft_ms"] - min_ttft) / (max_ttft - min_ttft))

        reset_factor = 0.0
        if weights["reset"] > 0 and account["reset_remaining_seconds"] is not None and min_reset is not None and max_reset is not None:
            if max_reset > min_reset:
                reset_factor = 1 - clamp01(
                    (account["reset_remaining_seconds"] - min_reset) / (max_reset - min_reset)
                )
            else:
                reset_factor = 1.0

        factors = {
            "priority": priority_factor,
            "load": load_factor,
            "queue": queue_factor,
            "error_rate": error_factor,
            "ttft": ttft_factor,
            "reset": reset_factor,
            "quota_headroom": account["quota_headroom_factor"] if weights["quota_headroom"] > 0 else 0.0,
            "upstream_cost": account["upstream_cost_factor"],
        }
        base_score = (
            weights["priority"] * factors["priority"]
            + weights["load"] * factors["load"]
            + weights["queue"] * factors["queue"]
            + weights["error_rate"] * factors["error_rate"]
            + weights["ttft"] * factors["ttft"]
            + weights["reset"] * factors["reset"]
            + weights["quota_headroom"] * factors["quota_headroom"]
            + weights["upstream_cost"] * (factors["upstream_cost"] - 0.5)
        )
        score = base_score
        if sticky_weighted:
            if account["previous_response_match"]:
                score += weights["previous_response"]
            if account["session_sticky_match"]:
                score += weights["session_sticky"]

        scored.append(
            {
                "account_ref": account["account_ref"],
                "score": round(score, 6),
                "base_score": round(base_score, 6),
                "factors": {name: round(value, 6) for name, value in factors.items()},
            }
        )

    scored.sort(key=lambda item: (-item["score"], item["account_ref"]))
    for rank, item in enumerate(scored, start=1):
        item["rank"] = rank
    return scored


def replay(raw: Any) -> dict[str, Any]:
    validated = validate_input(raw)
    current = score_accounts(validated["accounts"], validated["current_weights"], validated["sticky_weighted"])
    candidate = score_accounts(validated["accounts"], validated["candidate_weights"], validated["sticky_weighted"])
    current_ranks = {item["account_ref"]: item["rank"] for item in current}
    candidate_ranks = {item["account_ref"]: item["rank"] for item in candidate}
    rank_changes = [
        {
            "account_ref": account_ref,
            "current_rank": current_ranks[account_ref],
            "candidate_rank": candidate_ranks[account_ref],
            "rank_delta": current_ranks[account_ref] - candidate_ranks[account_ref],
        }
        for account_ref in sorted(current_ranks)
    ]
    return {
        "schema": RESULT_SCHEMA,
        "provider_calls": 0,
        "mutations": 0,
        "account_count": len(validated["accounts"]),
        "sticky_weighted": validated["sticky_weighted"],
        "current": {
            "weights": validated["current_weights"],
            "ranking": current,
        },
        "candidate": {
            "weights": validated["candidate_weights"],
            "ranking": candidate,
        },
        "rank_changes": rank_changes,
    }


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Compare current and candidate Sub2API scheduler weights without provider calls or mutations."
    )
    parser.add_argument("--input", type=Path, help="JSON fixture path; stdin is used when omitted")
    parser.add_argument("--pretty", action="store_true", help="pretty-print JSON output")
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv or sys.argv[1:])
    try:
        if args.input:
            raw = json.loads(args.input.read_text(encoding="utf-8"))
        else:
            raw = json.load(sys.stdin)
        result = replay(raw)
    except (OSError, json.JSONDecodeError, ReplayInputError) as exc:
        print(json.dumps({"schema": RESULT_SCHEMA, "error": str(exc)}, ensure_ascii=True), file=sys.stderr)
        return 2

    json.dump(result, sys.stdout, indent=2 if args.pretty else None, sort_keys=True)
    sys.stdout.write("\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
