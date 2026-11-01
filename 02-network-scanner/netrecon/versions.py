"""Tolerant version parsing and range matching (handles 8.9p1, 2.4.49, 4.91 ...)."""
from __future__ import annotations

import re


def parse(version: str) -> tuple[int, ...]:
    nums = re.findall(r"\d+", version)
    if not nums:
        raise ValueError(f"no numeric version in {version!r}")
    return tuple(int(n) for n in nums)


def _pad(a: tuple[int, ...], b: tuple[int, ...]) -> tuple[tuple[int, ...], tuple[int, ...]]:
    n = max(len(a), len(b))
    return a + (0,) * (n - len(a)), b + (0,) * (n - len(b))


def compare(a: str, b: str) -> int:
    pa, pb = _pad(parse(a), parse(b))
    return (pa > pb) - (pa < pb)


def matches(version: str, rule: dict) -> bool:
    """rule: {"exact": [...]} or {"min": "x", "max_exclusive": "y"} (either bound optional)."""
    try:
        if "exact" in rule:
            return any(compare(version, e) == 0 for e in rule["exact"])
        if "min" in rule and compare(version, rule["min"]) < 0:
            return False
        if "max_exclusive" in rule and compare(version, rule["max_exclusive"]) >= 0:
            return False
        return "min" in rule or "max_exclusive" in rule
    except ValueError:
        return False


def is_affected(version: str, rules: list[dict]) -> bool:
    return any(matches(version, r) for r in rules)
