"""Unit tests for c9s_kernel. Run with `pytest` from this directory."""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))

import pytest

from c9s_kernel import (
    Kernel,
    cve_evidence,
    cves_in_changelog,
    decide_verdict,
    parse_introducer,
    parse_public_date,
    release_counter,
)


# --------------------------------------------------------------------------- #
# Tiny parsers
# --------------------------------------------------------------------------- #

def test_release_counter():
    assert release_counter("700.el9") == 700
    assert release_counter("697.el9") == 697
    assert release_counter("garbage") is None


def test_parse_introducer():
    h = "CKI KWF Bot <a@b> [5.14.0-700.el9]"
    assert parse_introducer(h) == 700


def test_parse_introducer_missing():
    assert parse_introducer("plain header") is None


# --------------------------------------------------------------------------- #
# parse_public_date
# --------------------------------------------------------------------------- #

@pytest.mark.parametrize("s,expected", [
    ("2024-01-31T00:00:00Z", 1706659200),
    ("2024-01-31T00:00:00+00:00", 1706659200),
    ("2024-01-31T00:00:00", 1706659200),  # naive → assumed UTC
    (None, None),
    ("", None),
    ("not a date", None),
])
def test_parse_public_date(s, expected):
    assert parse_public_date(s) == expected


# --------------------------------------------------------------------------- #
# Kernel dataclass
# --------------------------------------------------------------------------- #

def test_kernel_str():
    assert str(Kernel("5.14.0", "697.el9")) == "kernel-5.14.0-697.el9"


def test_kernel_nvr():
    assert Kernel("5.14.0", "697.el9").nvr == "kernel-5.14.0-697.el9"


# --------------------------------------------------------------------------- #
# Changelog scanning
# --------------------------------------------------------------------------- #

def test_cves_in_changelog_extracts_and_dedupes():
    entries = [
        ("h1", "fix CVE-2025-12345 and CVE-2025-67890", 0),
        ("h2", "see CVE-2025-12345 again and CVE-2024-1086", 0),
    ]
    assert cves_in_changelog(entries) == {
        "CVE-2025-12345", "CVE-2025-67890", "CVE-2024-1086",
    }


def test_cves_in_changelog_ignores_close_matches():
    assert cves_in_changelog([("h", "CVE-2025-123 not valid", 0)]) == set()


def test_cve_evidence_returns_first_matching_line():
    entries = [
        ("h1", "no match", 0),
        ("h2", "intro\n- fix CVE-2025-12345 here\nmore", 0),
    ]
    assert cve_evidence(entries, "CVE-2025-12345") == "- fix CVE-2025-12345 here"


def test_cve_evidence_returns_none_when_unmentioned():
    assert cve_evidence([("h", "nothing here", 0)], "CVE-2025-12345") is None


# --------------------------------------------------------------------------- #
# decide_verdict — Stream-only verdict logic
# --------------------------------------------------------------------------- #

# Reference epochs: 2024-01-31 = 1706659200, 2024-06-01 = 1717200000

@pytest.mark.parametrize("src,evidence,intro,public,oldest,verdict", [
    # Own changelog hit → patched, regardless of anything else.
    (697, "- fix CVE-X", 700,  None, None, "patched"),
    (697, "- fix CVE-X", None, None, None, "patched"),
    # No own evidence, but cross-source introducer tells us:
    (697, None, 700,  None, None, "not_patched"),  # ours older than introducer
    (700, None, 700,  None, None, "patched"),      # equal
    (701, None, 700,  None, None, "patched"),      # ours newer
    # No introducer; fall back to public-date check.
    (697, None, None, 1717200000, 1706659200, "not_patched"),  # CVE public after window
    (697, None, None, 1706659200, 1717200000, "unknown"),      # CVE public before window
    (697, None, None, None,        1717200000, "not_patched"),  # missing public_date
    (697, None, None, 1717200000,  None,       "not_patched"),  # missing oldest
])
def test_decide_verdict(src, evidence, intro, public, oldest, verdict):
    got, _reason = decide_verdict(src, evidence, intro, public, oldest)
    assert got == verdict


def test_decide_verdict_introducer_takes_priority_over_public_date():
    """When we have a cross-source introducer, the date heuristic is irrelevant."""
    verdict, reason = decide_verdict(
        source_release=697,
        changelog_evidence=None,
        introducer_release=700,
        public_date_epoch=1706659200,   # would otherwise say "unknown"
        oldest_entry_epoch=1717200000,
    )
    assert verdict == "not_patched"
    assert "introducer" in reason
