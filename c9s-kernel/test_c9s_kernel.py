"""Unit tests for c9s_kernel.

Run with `pytest` from this directory.

These cover the pure-logic pieces only (RPM version comparison, NEVRA parsing,
changelog scanning, verdict calculation). The network-touching parts
(repodata, Koji, Red Hat security data) are not covered here — they're
exercised by the smoke tests in the README.
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
    evr_compare,
    parse_evr,
    rhel9_kernel_fix,
    rpmvercmp,
)


# --------------------------------------------------------------------------- #
# rpmvercmp — the rpm version-comparison primitive
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
    ("1.0~~", "1.0~", -1),
    # Caret sorts after end-of-string but before anything else (post-commit marker)
    ("1.0^", "1.0", 1),
    ("1.0^", "1.0a", -1),
    ("1.0^post", "1.1", -1),
    # Real-world RPM release strings
    ("697.el9", "427.13.1.el9_4", 1),
    ("697.el9", "700.el9", -1),
    ("697.el9", "697.el9", 0),
    # Combined version+release, separator is '-'
    ("5.14.0-700.el9", "5.14.0-697.el9", 1),
])
def test_rpmvercmp(a, b, expected):
    assert _sgn(rpmvercmp(a, b)) == expected, (
        f"rpmvercmp({a!r}, {b!r}) = {rpmvercmp(a, b)}, expected {expected}"
    )


@pytest.mark.parametrize("a,b", [
    ("1.0", "2.0"),
    ("697.el9", "427.13.1.el9_4"),
    ("1.0~rc1", "1.0"),
    ("5.14.0-700.el9", "5.14.0-697.el9"),
    ("1.10", "1.2"),
])
def test_rpmvercmp_antisymmetric(a, b):
    """rpmvercmp(a, b) must equal -rpmvercmp(b, a) (or both 0)."""
    assert _sgn(rpmvercmp(a, b)) == -_sgn(rpmvercmp(b, a))


# --------------------------------------------------------------------------- #
# evr_compare — (epoch, version, release) tuple ordering
# --------------------------------------------------------------------------- #

def test_evr_compare_epoch_dominates_everything():
    # Higher epoch wins even when version+release are much newer on the other side.
    assert evr_compare(("1", "1.0", "1"), ("0", "9.9", "999")) > 0
    assert evr_compare(("0", "9.9", "999"), ("1", "1.0", "1")) < 0


def test_evr_compare_version_then_release():
    assert evr_compare(("0", "5.14.0", "697.el9"),
                       ("0", "5.14.0", "700.el9")) < 0
    assert evr_compare(("0", "5.14.1", "1.el9"),
                       ("0", "5.14.0", "999.el9")) > 0


def test_evr_compare_default_epoch():
    """Empty-string epoch should be treated as 0."""
    assert evr_compare(("", "1.0", "1"), ("0", "1.0", "1")) == 0


def test_evr_compare_equal():
    assert evr_compare(("0", "5.14.0", "697.el9"),
                       ("0", "5.14.0", "697.el9")) == 0


# --------------------------------------------------------------------------- #
# parse_evr — split "kernel-0:5.14.0-427.13.1.el9_4" into (E, V, R)
# --------------------------------------------------------------------------- #

def test_parse_evr_with_epoch():
    assert parse_evr("kernel-0:5.14.0-427.13.1.el9_4") == ("0", "5.14.0", "427.13.1.el9_4")


def test_parse_evr_without_epoch():
    assert parse_evr("kernel-5.14.0-697.el9") == ("0", "5.14.0", "697.el9")


def test_parse_evr_nonzero_epoch():
    assert parse_evr("kernel-2:5.14.0-697.el9") == ("2", "5.14.0", "697.el9")


def test_parse_evr_invalid():
    assert parse_evr("kernel") is None
    assert parse_evr("") is None


def test_parse_evr_then_compare():
    """End-to-end: parse two NEVRAs then verify the version verdict."""
    ours = parse_evr("kernel-5.14.0-697.el9")
    fix = parse_evr("kernel-0:5.14.0-427.13.1.el9_4")
    assert evr_compare(ours, fix) > 0  # 697 > 427 → patched


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
    # The regex requires CVE-YYYY-NNNN with 4-7 digits; a 3-digit tail shouldn't match.
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
# rhel9_kernel_fix — extract the fixed NEVRA from a Red Hat CVE record
# --------------------------------------------------------------------------- #

def test_rhel9_kernel_fix_picks_rhel9_kernel_entry():
    data = {"affected_release": [
        {"product_name": "Red Hat Enterprise Linux 7",
         "package": "kernel-0:3.10.0-1234.el7"},
        {"product_name": "Red Hat Enterprise Linux 9",
         "package": "kernel-0:5.14.0-427.13.1.el9_4"},
    ]}
    fix = rhel9_kernel_fix(data)
    assert fix is not None
    assert fix["package"] == "kernel-0:5.14.0-427.13.1.el9_4"


def test_rhel9_kernel_fix_skips_non_kernel_packages():
    """kpatch-patch and friends shouldn't satisfy the kernel match."""
    data = {"affected_release": [
        {"product_name": "Red Hat Enterprise Linux 9", "package": "kpatch-patch"},
    ]}
    assert rhel9_kernel_fix(data) is None


def test_rhel9_kernel_fix_returns_none_when_no_rhel9():
    data = {"affected_release": [
        {"product_name": "Red Hat Enterprise Linux 7",
         "package": "kernel-0:3.10.0-1234.el7"},
    ]}
    assert rhel9_kernel_fix(data) is None


def test_rhel9_kernel_fix_handles_empty_input():
    assert rhel9_kernel_fix({}) is None
    assert rhel9_kernel_fix({"affected_release": []}) is None


def test_rhel9_kernel_fix_returns_first_match():
    """Multiple RHEL 9 kernel rows: should return the first."""
    data = {"affected_release": [
        {"product_name": "Red Hat Enterprise Linux 9",
         "package": "kernel-0:5.14.0-100.el9"},
        {"product_name": "Red Hat Enterprise Linux 9",
         "package": "kernel-0:5.14.0-200.el9"},
    ]}
    fix = rhel9_kernel_fix(data)
    assert fix["package"] == "kernel-0:5.14.0-100.el9"


# --------------------------------------------------------------------------- #
# decide_verdict — combine the two signals into PATCHED / NOT PATCHED
# --------------------------------------------------------------------------- #

@pytest.mark.parametrize("version_patched,evidence,expected_verdict,expected_reason", [
    # Version comparison says we're past the fix → patched, period.
    (True,  None,           "patched",     "kernel >= RHEL9 fix"),
    (True,  "some line",    "patched",     "kernel >= RHEL9 fix"),
    # No Red Hat record but changelog mentions the CVE → patched via backport.
    (None,  "evidence",     "patched",     "backport in changelog"),
    # Version says we're behind, but changelog mentions it → trust the changelog.
    # (Edge case: a build that includes the CVE ID but isn't yet at the RHEL fix tag.)
    (False, "evidence",     "patched",     "backport in changelog"),
    # Version says we're behind and no evidence → not patched, version-grounded.
    (False, None,           "not_patched", "kernel older than RHEL9 fix"),
    # No Red Hat record AND no changelog evidence → "no kernel covers this yet".
    (None,  None,           "not_patched", "no fix in changelog or Red Hat data"),
])
def test_decide_verdict(version_patched, evidence, expected_verdict, expected_reason):
    verdict, reason = decide_verdict(version_patched, evidence)
    assert verdict == expected_verdict
    assert reason == expected_reason
