#!/usr/bin/env python3
"""
c9s-kernel — Track CentOS Stream 9 kernel availability and CVE patch status.

Subcommands:
    latest                       Show newest kernel NVRs across released / pending / gate.
    check CVE-YYYY-NNNNN [...]   Verdict per source.
    changelog [--source SRC]     Dump the kernel changelog for a given source.
    cves      [--source SRC]     List every CVE referenced in a kernel's changelog.

Sources:
    released  CentOS Stream 9 BaseOS x86_64 (mirror.stream.centos.org)
    pending   Koji c9s-pending tag (newest signed builds, ahead of the compose)
    gate      Koji c9s-gate tag (passed gating, between pending and released)

External APIs:
    https://mirror.stream.centos.org/9-stream/BaseOS/x86_64/os/repodata
    https://kojihub.stream.centos.org/kojihub  (XML-RPC)
    https://access.redhat.com/hydra/rest/securitydata/cve/<id>.json
"""

from __future__ import annotations

import argparse
import gzip
import io
import json
import re
import sys
import urllib.request
import xml.etree.ElementTree as ET
import xmlrpc.client
from dataclasses import dataclass
from datetime import datetime, timezone

REPO_BASE = "https://mirror.stream.centos.org/9-stream/BaseOS/x86_64/os"
KOJI_URL = "https://kojihub.stream.centos.org/kojihub"
REDHAT_CVE_URL = "https://access.redhat.com/hydra/rest/securitydata/cve/{cve}.json"

USER_AGENT = "c9s-kernel/0.1"
COMMON_NS = "http://linux.duke.edu/metadata/common"
REPO_NS = "http://linux.duke.edu/metadata/repo"

CVE_RE = re.compile(r"CVE-\d{4}-\d{4,7}")
# Match the build-counter integer from a kernel changelog entry header
# like '... [5.14.0-700.el9]'. Stream 9 kernels are always integer + .el9.
INTRODUCER_RE = re.compile(r"-(\d+)\.el9")

SOURCES = ("released", "pending", "gate")


# --------------------------------------------------------------------------- #
# Helpers
# --------------------------------------------------------------------------- #

@dataclass
class Kernel:
    version: str
    release: str

    @property
    def nvr(self) -> str:
        return f"kernel-{self.version}-{self.release}"

    def __str__(self) -> str:
        return self.nvr


def http_get(url: str) -> bytes:
    req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
    with urllib.request.urlopen(req, timeout=60) as resp:
        return resp.read()


def release_counter(release: str) -> int | None:
    """Pull the leading integer build counter out of a release string like '700.el9'."""
    m = re.match(r"\d+", release)
    return int(m.group(0)) if m else None


def parse_introducer(header: str) -> int | None:
    """Pull the build counter from a changelog entry header's '[V-N.el9]' label."""
    m = INTRODUCER_RE.search(header)
    return int(m.group(1)) if m else None


def parse_public_date(s: str | None) -> int | None:
    """Parse Red Hat's ISO-8601 public_date to epoch seconds."""
    if not s:
        return None
    try:
        dt = datetime.fromisoformat(s.replace("Z", "+00:00"))
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return int(dt.timestamp())
    except (ValueError, TypeError):
        return None


# --------------------------------------------------------------------------- #
# Released kernel: BaseOS repodata
# --------------------------------------------------------------------------- #

def latest_released_kernel() -> Kernel:
    repomd = ET.fromstring(http_get(f"{REPO_BASE}/repodata/repomd.xml"))
    href = None
    for d in repomd.findall(f"{{{REPO_NS}}}data"):
        if d.get("type") == "primary":
            loc = d.find(f"{{{REPO_NS}}}location")
            href = loc.get("href") if loc is not None else None
    if href is None:
        raise RuntimeError("primary data block not found in repomd.xml")

    xml_bytes = gzip.decompress(http_get(f"{REPO_BASE}/{href}"))
    pkg_tag = f"{{{COMMON_NS}}}package"

    best: Kernel | None = None
    best_buildtime = -1
    for _ev, elem in ET.iterparse(io.BytesIO(xml_bytes), events=("end",)):
        if elem.tag != pkg_tag:
            continue
        name_el = elem.find(f"{{{COMMON_NS}}}name")
        arch_el = elem.find(f"{{{COMMON_NS}}}arch")
        if (name_el is None or name_el.text != "kernel"
                or arch_el is None or arch_el.text != "x86_64"):
            elem.clear()
            continue
        ver = elem.find(f"{{{COMMON_NS}}}version")
        bt = elem.find(f"{{{COMMON_NS}}}time")
        buildtime = int(bt.get("build", "0")) if bt is not None else 0
        k = Kernel(
            version=ver.get("ver", "") if ver is not None else "",
            release=ver.get("rel", "") if ver is not None else "",
        )
        if buildtime > best_buildtime:
            best, best_buildtime = k, buildtime
        elem.clear()

    if best is None:
        raise RuntimeError("no kernel package found in BaseOS primary metadata")
    return best


# --------------------------------------------------------------------------- #
# Koji
# --------------------------------------------------------------------------- #

def _koji() -> xmlrpc.client.ServerProxy:
    return xmlrpc.client.ServerProxy(KOJI_URL, allow_none=True)


def latest_tagged_kernel(tag: str) -> Kernel | None:
    builds = _koji().getLatestBuilds(tag, None, "kernel")
    if not builds:
        return None
    b = builds[0]
    return Kernel(version=b["version"], release=b["release"])


def kernel_changelog(nvr: str) -> list[tuple[str, str, int]]:
    """Return [(header, body, epoch_seconds), ...] newest first, from the SRPM headers."""
    s = _koji()
    build = s.getBuild(nvr)
    if not build:
        raise RuntimeError(f"Koji has no build {nvr}")
    srpms = [r for r in s.listRPMs(build["build_id"]) if r["arch"] == "src"]
    if not srpms:
        raise RuntimeError(f"build {nvr} has no SRPM listed")
    hdrs = s.getRPMHeaders(srpms[0]["id"], ["changelogtime", "changelogname", "changelogtext"])
    return list(zip(
        hdrs.get("CHANGELOGNAME") or [],
        hdrs.get("CHANGELOGTEXT") or [],
        hdrs.get("CHANGELOGTIME") or [],
    ))


def cves_in_changelog(entries: list[tuple[str, str, int]]) -> set[str]:
    found: set[str] = set()
    for _h, body, _t in entries:
        found.update(CVE_RE.findall(body))
    return found


def cve_evidence(entries: list[tuple[str, str, int]], cve: str) -> str | None:
    """First line in any entry that mentions the CVE."""
    for _h, body, _t in entries:
        for line in body.splitlines():
            if cve in line:
                return line.strip()
    return None


def evidence_and_introducer(entries: list[tuple[str, str, int]],
                            cve: str) -> tuple[str | None, int | None]:
    """Find (evidence line, introducer build counter) for the CVE in this changelog."""
    for header, body, _t in entries:
        if cve not in body:
            continue
        line = next((ln.strip() for ln in body.splitlines() if cve in ln), None)
        return line, parse_introducer(header)
    return None, None


def redhat_cve(cve: str) -> dict:
    return json.loads(http_get(REDHAT_CVE_URL.format(cve=cve)))


# --------------------------------------------------------------------------- #
# Verdict
# --------------------------------------------------------------------------- #

def decide_verdict(source_release: int | None,
                   changelog_evidence: str | None,
                   introducer_release: int | None,
                   public_date_epoch: int | None,
                   oldest_entry_epoch: int | None) -> tuple[str, str]:
    """Stream-only verdict. See README for the signal priority."""
    if changelog_evidence:
        return "patched", "fix in changelog"

    if introducer_release is not None and source_release is not None:
        if source_release >= introducer_release:
            return "patched", f"build at or past introducer 5.14.0-{introducer_release}.el9"
        return "not_patched", f"build older than introducer 5.14.0-{introducer_release}.el9"

    if public_date_epoch is None or oldest_entry_epoch is None:
        return "not_patched", "no fix in changelog"

    if public_date_epoch >= oldest_entry_epoch:
        return "not_patched", "no fix in changelog (CVE public after oldest entry)"

    return "unknown", "fix predates visible changelog window"


# --------------------------------------------------------------------------- #
# Source dispatch
# --------------------------------------------------------------------------- #

def resolve_source(source: str) -> Kernel | None:
    if source == "released":
        return latest_released_kernel()
    if source == "pending":
        return latest_tagged_kernel("c9s-pending")
    if source == "gate":
        return latest_tagged_kernel("c9s-gate")
    raise ValueError(f"unknown source: {source}")


# --------------------------------------------------------------------------- #
# Subcommands
# --------------------------------------------------------------------------- #

def cmd_latest(args) -> int:
    out: dict[str, str | None] = {}
    for src in SOURCES:
        try:
            k = resolve_source(src)
            out[src] = str(k) if k else None
        except Exception as e:
            out[src] = f"<error: {e}>"
    if args.json:
        print(json.dumps(out, indent=2))
    else:
        for s in SOURCES:
            print(f"{s:9s} {out[s] or '(none)'}")
    return 0


def cmd_check(args) -> int:
    findings: list[dict] = []
    for raw in args.cve:
        cve = raw.upper()
        if not CVE_RE.fullmatch(cve):
            print(f"warning: skipping {raw!r} — not a valid CVE ID", file=sys.stderr)
            continue
        result: dict = {"cve": cve, "sources": {}, "redhat": None}

        public_date_epoch: int | None = None
        try:
            data = redhat_cve(cve)
            result["redhat"] = {
                "severity": data.get("threat_severity"),
                "public_date": data.get("public_date"),
            }
            public_date_epoch = parse_public_date(data.get("public_date"))
        except Exception as e:
            result["redhat"] = {"error": str(e)}

        # Pass 1: collect each source's data and any introducer we can spot.
        introducer: int | None = None
        result["fixed_in"] = None  # filled in once we know the introducer
        for src in SOURCES:
            try:
                kernel = resolve_source(src)
            except Exception as e:
                result["sources"][src] = {"error": f"resolve: {e}"}
                continue
            if kernel is None:
                result["sources"][src] = {"nvr": None}
                continue

            entry: dict = {"nvr": kernel.nvr, "_release": release_counter(kernel.release)}
            try:
                entries = kernel_changelog(kernel.nvr)
                evidence, src_introducer = evidence_and_introducer(entries, cve)
                entry["changelog_evidence"] = evidence
                entry["oldest_entry_epoch"] = (
                    min(t for _h, _b, t in entries) if entries else None
                )
                if src_introducer is not None and introducer is None:
                    introducer = src_introducer
            except Exception as e:
                entry["changelog_error"] = str(e)
                entry["changelog_evidence"] = None
                entry["oldest_entry_epoch"] = None
            result["sources"][src] = entry

        # Pass 2: decide each source's verdict using the introducer + own evidence.
        for src in SOURCES:
            entry = result["sources"].get(src) or {}
            if "error" in entry or entry.get("nvr") is None:
                continue
            entry["verdict"], entry["reason"] = decide_verdict(
                source_release=entry.pop("_release"),
                changelog_evidence=entry["changelog_evidence"],
                introducer_release=introducer,
                public_date_epoch=public_date_epoch,
                oldest_entry_epoch=entry["oldest_entry_epoch"],
            )

        if introducer is not None:
            result["fixed_in"] = f"kernel-5.14.0-{introducer}.el9"

        findings.append(result)

    if args.json:
        print(json.dumps(findings, indent=2))
    else:
        for f in findings:
            print(f"=== {f['cve']} ===")
            rh = f.get("redhat") or {}
            if "error" in rh:
                print(f"  Red Hat:   error: {rh['error']}")
            else:
                print(f"  Severity:    {rh.get('severity') or '?'}")
                print(f"  Public date: {(rh.get('public_date') or '?')[:10]}")
            print(f"  Fixed in:    {f.get('fixed_in') or '(unknown — fix not visible in any changelog)'}")
            print()
            for src in SOURCES:
                s = f["sources"].get(src, {})
                if "error" in s:
                    print(f"  {src:10s} ERROR: {s['error']}")
                    continue
                if s.get("nvr") is None:
                    print(f"  {src:10s} (no kernel found)")
                    continue
                label = {"patched": "PATCHED",
                         "not_patched": "NOT PATCHED",
                         "unknown": "UNKNOWN"}[s["verdict"]]
                print(f"  {src:10s} {label:12s} {s.get('reason', '')}")
                if s.get("changelog_evidence"):
                    print(f"             evidence: {s['changelog_evidence']}")
            print()

    any_not_patched = any(
        s.get("verdict") == "not_patched"
        for f in findings for s in f["sources"].values()
        if isinstance(s, dict)
    )
    return 1 if any_not_patched else 0


def cmd_changelog(args) -> int:
    kernel = resolve_source(args.source)
    if kernel is None:
        print(f"no kernel found for source {args.source}", file=sys.stderr)
        return 2
    entries = kernel_changelog(kernel.nvr)
    print(f"# {kernel} — {len(entries)} changelog entries\n")
    for header, body, _t in (entries[: args.limit] if args.limit else entries):
        print(f"* {header}\n{body}\n")
    return 0


def cmd_cves(args) -> int:
    kernel = resolve_source(args.source)
    if kernel is None:
        print(f"no kernel found for source {args.source}", file=sys.stderr)
        return 2
    entries = kernel_changelog(kernel.nvr)
    cves = sorted(cves_in_changelog(entries), reverse=True)
    if args.json:
        print(json.dumps({"source": args.source, "nvr": kernel.nvr, "cves": cves}, indent=2))
    else:
        print(f"# {len(cves)} CVEs referenced in {kernel} changelog")
        for c in cves:
            print(c)
    return 0


# --------------------------------------------------------------------------- #
# Entrypoint
# --------------------------------------------------------------------------- #

def main(argv: list[str] | None = None) -> int:
    common = argparse.ArgumentParser(add_help=False)
    common.add_argument("--json", action="store_true", help="machine-readable output")

    p = argparse.ArgumentParser(prog="c9s-kernel", description=__doc__,
                                formatter_class=argparse.RawDescriptionHelpFormatter,
                                parents=[common])
    sub = p.add_subparsers(dest="cmd", required=True)

    sub.add_parser("latest", parents=[common],
                   help="show newest kernel across released/pending/gate"
                   ).set_defaults(func=cmd_latest)

    sp = sub.add_parser("check", parents=[common],
                        help="verdict per source for one or more CVEs")
    sp.add_argument("cve", nargs="+", help="one or more CVE IDs (e.g. CVE-2024-1086)")
    sp.set_defaults(func=cmd_check)

    sp = sub.add_parser("changelog", parents=[common],
                        help="dump kernel changelog for a source")
    sp.add_argument("--source", choices=SOURCES, default="released")
    sp.add_argument("--limit", type=int, default=0, help="show only the first N entries")
    sp.set_defaults(func=cmd_changelog)

    sp = sub.add_parser("cves", parents=[common],
                        help="list every CVE referenced in a kernel changelog")
    sp.add_argument("--source", choices=SOURCES, default="released")
    sp.set_defaults(func=cmd_cves)

    args = p.parse_args(argv)
    try:
        return args.func(args)
    except KeyboardInterrupt:
        return 130


if __name__ == "__main__":
    sys.exit(main())
