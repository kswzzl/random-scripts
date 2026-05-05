"""Unit tests for c9s_kernel.

Run with `pytest` from this directory.

Covers the pure-logic pieces only — Stream-vs-Stream version comparison,
NEVRA formatting, changelog scanning, public-date parsing, introducer
parsing, and the verdict decision. Network-touching code paths (repodata,
Koji, Red Hat security data) are exercised by running the CLI.
"""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))

import pytest

from c9s_kernel import (
    Nevra,
    cve_evidence,
    cves_in_changelog,
    decide_verdict,
    parse_introducer_vr,
    parse_public_date,
    rpmvercmp,
    vr_compare,
)


# --------------------------------------------------------------------------- #
# rpmvercmp — Stream-vs-Stream RPM version comparison
# --------------------------------------------------------------------------- #

def _sgn(n: int) -> int:
    return 0 if n == 0 else (1 if n > 0 else -1)


@pytest.mark.parametrize("a,b,expected", [
    # Equal
    ("", "", 0),
    ("1.0", "1.0", 0),
    ("5.14.0", "5.14.0", 0),
    # Simple numeric
    ("1.0", "2.0", -1),
    ("2.0", "1.0", 1),
    # Numeric, not lexical
    ("1.10", "1.2", 1),
    ("10", "9", 1),
    # Leading zeros
    ("01", "1", 0),
    ("1.0", "1.00", 0),
    # Extra trailing segment makes it newer
    ("1.0a", "1.0", 1),
    ("1.0", "1.0a", -1),
    # Tilde sorts before everything (pre-release marker)
    ("1.0~rc1", "1.0", -1),
    ("1.0", "1.0~rc1", 1),
    ("1.0~rc1", "1.0~rc2", -1),
    # Caret sorts after end-of-string but before anything else
    ("1.0^", "1.0", 1),
    ("1.0^", "1.0a", -1),
    # Real-world Stream release strings
    ("697.el9", "700.el9", -1),
    ("700.el9", "697.el9", 1),
    ("697.el9", "697.el9", 0),
    ("700.el9", "698.el9", 1),
    # Combined version-release as one string
    ("5.14.0-700.el9", "5.14.0-697.el9", 1),
])
def test_rpmvercmp(a, b, expected):
    assert _sgn(rpmvercmp(a, b)) == expected


@pytest.mark.parametrize("a,b", [
    ("1.0", "2.0"),
    ("697.el9", "700.el9"),
    ("1.0~rc1", "1.0"),
    ("1.10", "1.2"),
])
def test_rpmvercmp_antisymmetric(a, b):
    """rpmvercmp(a,b) and rpmvercmp(b,a) should have opposite signs (or both 0)."""
    assert _sgn(rpmvercmp(a, b)) == -_sgn(rpmvercmp(b, a))


# --------------------------------------------------------------------------- #
# vr_compare — (version, release) tuple ordering
# --------------------------------------------------------------------------- #

def test_vr_compare_version_dominates():
    assert vr_compare(("5.14.1", "1.el9"), ("5.14.0", "999.el9")) > 0


def test_vr_compare_falls_through_to_release():
    assert vr_compare(("5.14.0", "697.el9"), ("5.14.0", "700.el9")) < 0


def test_vr_compare_equal():
    assert vr_compare(("5.14.0", "697.el9"), ("5.14.0", "697.el9")) == 0


# --------------------------------------------------------------------------- #
# parse_introducer_vr — pull '[5.14.0-700.el9]' off a changelog header
# --------------------------------------------------------------------------- #

def test_parse_introducer_vr_basic():
    h = "CKI KWF Bot <cki-ci-bot+kwf-gitlab-com@redhat.com> [5.14.0-700.el9]"
    assert parse_introducer_vr(h) == ("5.14.0", "700.el9")


def test_parse_introducer_vr_picks_last_bracketed():
    """If the header has multiple bracketed tokens, the build label is last."""
    h = "Foo [misc note] [5.14.0-697.el9]"
    assert parse_introducer_vr(h) == ("5.14.0", "697.el9")


def test_parse_introducer_vr_missing_returns_none():
    assert parse_introducer_vr("plain header with no brackets") is None


def test_parse_introducer_vr_no_hyphen_returns_none():
    """If the bracketed token has no hyphen, there's no V-R structure to parse."""
    assert parse_introducer_vr("Foo [nohyphen]") is None


def test_parse_introducer_vr_splits_on_last_hyphen():
    """V-R splits on the rightmost hyphen, so versions with hyphens stay together."""
    # In practice kernel headers don't have hyphens in V, but document the behavior.
    assert parse_introducer_vr("[some-multi-part-release]") == ("some-multi-part", "release")


def test_parse_introducer_vr_handles_non_kernel_release_format():
    """V-R tokens with multi-segment versions (e.g. 5.14.0) parse correctly."""
    h = "Some Author <a@b> [5.14.0-503.50.1.el9_5]"
    assert parse_introducer_vr(h) == ("5.14.0", "503.50.1.el9_5")


# --------------------------------------------------------------------------- #
# Nevra dataclass
# --------------------------------------------------------------------------- #

def test_nevra_str_omits_zero_epoch():
    assert str(Nevra("kernel", "0", "5.14.0", "697.el9")) == "kernel-5.14.0-697.el9"


def test_nevra_str_includes_nonzero_epoch():
    assert str(Nevra("kernel", "2", "5.14.0", "697.el9")) == "kernel-2:5.14.0-697.el9"


def test_nevra_nvr_never_includes_epoch():
    assert Nevra("kernel", "2", "5.14.0", "697.el9").nvr == "kernel-5.14.0-697.el9"


# --------------------------------------------------------------------------- #
# Changelog scanning
# --------------------------------------------------------------------------- #

def test_cves_in_changelog_extracts_all():
    entries = [
        ("hdr1", "fix CVE-2025-12345 and CVE-2025-67890", 0),
        ("hdr2", "see CVE-2024-1086", 0),
    ]
    assert cves_in_changelog(entries) == {
        "CVE-2025-12345", "CVE-2025-67890", "CVE-2024-1086",
    }


def test_cves_in_changelog_deduplicates_across_entries():
    entries = [
        ("hdr1", "CVE-2025-12345 first time", 0),
        ("hdr2", "CVE-2025-12345 second time", 0),
    ]
    assert cves_in_changelog(entries) == {"CVE-2025-12345"}


def test_cves_in_changelog_empty():
    assert cves_in_changelog([]) == set()
    assert cves_in_changelog([("hdr", "no cves here", 0)]) == set()


def test_cves_in_changelog_ignores_close_matches():
    # CVE-YYYY-NNNN requires 4-7 digits in the tail; 3 digits shouldn't match.
    assert cves_in_changelog([("hdr", "CVE-2025-123 not valid", 0)]) == set()


def test_cve_evidence_returns_matching_line():
    entries = [
        ("hdr", "intro line\n- fix something CVE-2025-12345 thing\nmore stuff", 0),
    ]
    assert cve_evidence(entries, "CVE-2025-12345") == "- fix something CVE-2025-12345 thing"


def test_cve_evidence_returns_none_when_unmentioned():
    entries = [("hdr", "nothing here", 0)]
    assert cve_evidence(entries, "CVE-2025-12345") is None


def test_cve_evidence_finds_first_matching_entry():
    entries = [
        ("hdr1", "no match", 0),
        ("hdr2", "match here: CVE-2025-12345 line two", 0),
        ("hdr3", "another CVE-2025-12345 later", 0),
    ]
    assert cve_evidence(entries, "CVE-2025-12345") == "match here: CVE-2025-12345 line two"


# --------------------------------------------------------------------------- #
# parse_public_date — Red Hat ISO-8601 to epoch
# --------------------------------------------------------------------------- #

def test_parse_public_date_redhat_format():
    # 2024-01-31T00:00:00 UTC = 1706659200
    assert parse_public_date("2024-01-31T00:00:00Z") == 1706659200


def test_parse_public_date_with_timezone_offset():
    assert parse_public_date("2024-01-31T00:00:00+00:00") == 1706659200


def test_parse_public_date_naive_datetime_assumed_utc():
    assert parse_public_date("2024-01-31T00:00:00") == 1706659200


def test_parse_public_date_none_or_empty():
    assert parse_public_date(None) is None
    assert parse_public_date("") is None


def test_parse_public_date_garbage():
    assert parse_public_date("not a date") is None


# --------------------------------------------------------------------------- #
# decide_verdict — Stream-only verdict logic
# --------------------------------------------------------------------------- #

# Reference epochs:
#   2024-01-31 UTC = 1706659200
#   2024-06-01 UTC = 1717200000
#   2024-12-01 UTC = 1733011200

OUR_VR = ("5.14.0", "697.el9")
NEWER_VR = ("5.14.0", "700.el9")
OLDER_VR = ("5.14.0", "690.el9")


def test_verdict_own_changelog_hit_is_definitive_patched():
    verdict, reason = decide_verdict(
        source_vr=OUR_VR,
        changelog_evidence="- fix CVE-X line",
        introducer_vr=NEWER_VR,  # even if introducer is newer, our own evidence wins
        public_date_epoch=1717200000,
        oldest_entry_epoch=1706659200,
    )
    assert verdict == "patched"
    assert reason == "fix in changelog"


def test_verdict_own_evidence_overrides_missing_metadata():
    verdict, _ = decide_verdict(
        source_vr=OUR_VR,
        changelog_evidence="- fix CVE-X",
        introducer_vr=None,
        public_date_epoch=None,
        oldest_entry_epoch=None,
    )
    assert verdict == "patched"


def test_verdict_introducer_older_means_patched():
    """Fix landed in 690.el9; we're at 697.el9 → patched, fix has rolled off."""
    verdict, reason = decide_verdict(
        source_vr=OUR_VR,
        changelog_evidence=None,
        introducer_vr=OLDER_VR,
        public_date_epoch=None,
        oldest_entry_epoch=None,
    )
    assert verdict == "patched"
    assert "5.14.0-690.el9" in reason


def test_verdict_introducer_newer_means_not_patched():
    """Fix landed in 700.el9; we're at 697.el9 → not patched, fix is in a future build."""
    verdict, reason = decide_verdict(
        source_vr=OUR_VR,
        changelog_evidence=None,
        introducer_vr=NEWER_VR,
        public_date_epoch=None,
        oldest_entry_epoch=None,
    )
    assert verdict == "not_patched"
    assert "5.14.0-700.el9" in reason


def test_verdict_introducer_equal_means_patched():
    """Fix landed exactly in our build (we just don't see it because it rolled off)."""
    verdict, _ = decide_verdict(
        source_vr=OUR_VR,
        changelog_evidence=None,
        introducer_vr=OUR_VR,
        public_date_epoch=None,
        oldest_entry_epoch=None,
    )
    assert verdict == "patched"


def test_verdict_no_introducer_recent_cve_falls_through_to_not_patched():
    """No source has evidence; CVE public AFTER our oldest entry → not patched."""
    verdict, reason = decide_verdict(
        source_vr=OUR_VR,
        changelog_evidence=None,
        introducer_vr=None,
        public_date_epoch=1733011200,   # Dec 2024
        oldest_entry_epoch=1717200000,  # Jun 2024
    )
    assert verdict == "not_patched"
    assert "CVE public after oldest entry" in reason


def test_verdict_no_introducer_old_cve_is_unknown():
    """No source has evidence; CVE public BEFORE our oldest entry → unknown."""
    verdict, reason = decide_verdict(
        source_vr=OUR_VR,
        changelog_evidence=None,
        introducer_vr=None,
        public_date_epoch=1706659200,   # Jan 2024
        oldest_entry_epoch=1717200000,  # Jun 2024
    )
    assert verdict == "unknown"
    assert "predates" in reason


def test_verdict_no_introducer_no_metadata_falls_through_to_not_patched():
    verdict, _ = decide_verdict(
        source_vr=OUR_VR,
        changelog_evidence=None,
        introducer_vr=None,
        public_date_epoch=None,
        oldest_entry_epoch=1717200000,
    )
    assert verdict == "not_patched"


def test_verdict_introducer_takes_priority_over_public_date():
    """If we have a Stream introducer, that's authoritative — ignore public_date."""
    verdict, reason = decide_verdict(
        source_vr=OUR_VR,
        changelog_evidence=None,
        introducer_vr=NEWER_VR,
        public_date_epoch=1706659200,   # Jan 2024 (would otherwise say "unknown")
        oldest_entry_epoch=1717200000,  # Jun 2024
    )
    assert verdict == "not_patched"
    assert "introducer" in reason
