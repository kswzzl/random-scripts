#!/usr/bin/env python3
"""
c9s-kernel — Track CentOS Stream 9 kernel availability and CVE patch status.

Subcommands:
    latest                       Show newest kernel NEVRAs across released / pending / gate.
    check CVE-YYYY-NNNNN [...]   Report which sources have changelog evidence of the fix.
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

REPO_BASE = "https://mirror.stream.centos.org/9-stream/BaseOS/x86_64/os"
KOJI_URL = "https://kojihub.stream.centos.org/kojihub"
REDHAT_CVE_URL = "https://access.redhat.com/hydra/rest/securitydata/cve/{cve}.json"

USER_AGENT = "c9s-kernel/0.1"

REPO_NS = {
    "r": "http://linux.duke.edu/metadata/repo",
    "c": "http://linux.duke.edu/metadata/common",
}

CVE_RE = re.compile(r"CVE-\d{4}-\d{4,7}")
SOURCES = ("released", "pending", "gate")


# --------------------------------------------------------------------------- #
# RPM version comparison (rpmvercmp algorithm)
# --------------------------------------------------------------------------- #

def rpmvercmp(a: str, b: str) -> int:
    """Compare two RPM version/release strings. Returns -1 / 0 / 1."""
    if a == b:
        return 0
    i = j = 0
    while i < len(a) and j < len(b):
        if a[i] == "~" or b[j] == "~":
            if a[i] != "~":
                return 1
            if b[j] != "~":
                return -1
            i += 1
            j += 1
            continue
        if a[i] == "^" or b[j] == "^":
            if i == len(a):
                return -1
            if j == len(b):
                return 1
            if a[i] != "^":
                return 1
            if b[j] != "^":
                return -1
            i += 1
            j += 1
            continue
        if not a[i].isalnum():
            i += 1
            continue
        if not b[j].isalnum():
            j += 1
            continue
        if a[i].isdigit():
            ma = re.match(r"\d+", a[i:])
            seg_a = ma.group(0)
            i += len(seg_a)
            isnum_a = True
        else:
            ma = re.match(r"[A-Za-z]+", a[i:])
            seg_a = ma.group(0)
            i += len(seg_a)
            isnum_a = False
        if b[j].isdigit():
            mb = re.match(r"\d+", b[j:])
            seg_b = mb.group(0)
            j += len(seg_b)
            isnum_b = True
        else:
            mb = re.match(r"[A-Za-z]+", b[j:])
            seg_b = mb.group(0)
            j += len(seg_b)
            isnum_b = False
        if isnum_a and not isnum_b:
            return 1
        if not isnum_a and isnum_b:
            return -1
        if isnum_a:
            seg_a = seg_a.lstrip("0") or "0"
            seg_b = seg_b.lstrip("0") or "0"
            if len(seg_a) != len(seg_b):
                return 1 if len(seg_a) > len(seg_b) else -1
        if seg_a != seg_b:
            return 1 if seg_a > seg_b else -1
    if i == len(a) and j == len(b):
        return 0
    rem = a[i:] if i < len(a) else b[j:]
    if rem.startswith("~"):
        return -1 if i < len(a) else 1
    return 1 if i < len(a) else -1


def evr_compare(a: tuple[str, str, str], b: tuple[str, str, str]) -> int:
    ea, va, ra = a
    eb, vb, rb = b
    c = rpmvercmp(ea or "0", eb or "0")
    if c:
        return c
    c = rpmvercmp(va, vb)
    if c:
        return c
    return rpmvercmp(ra, rb)


def parse_evr(s: str) -> tuple[str, str, str] | None:
    """Parse 'kernel-0:5.14.0-427.13.1.el9_4' or 'kernel-5.14.0-697.el9' into (E, V, R)."""
    if "-" not in s:
        return None
    _name, rest = s.split("-", 1)
    epoch = "0"
    if ":" in rest.split("-", 1)[0]:
        epoch, rest = rest.split(":", 1)
    if "-" not in rest:
        return None
    version, release = rest.rsplit("-", 1)
    return epoch, version, release


# --------------------------------------------------------------------------- #
# HTTP
# --------------------------------------------------------------------------- #

def http_get(url: str) -> bytes:
    req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
    with urllib.request.urlopen(req, timeout=60) as resp:
        return resp.read()


# --------------------------------------------------------------------------- #
# NEVRA
# --------------------------------------------------------------------------- #

@dataclass
class Nevra:
    name: str
    epoch: str
    version: str
    release: str

    @property
    def nvr(self) -> str:
        return f"{self.name}-{self.version}-{self.release}"

    def __str__(self) -> str:
        e = f"{self.epoch}:" if self.epoch and self.epoch != "0" else ""
        return f"{self.name}-{e}{self.version}-{self.release}"


# --------------------------------------------------------------------------- #
# Released kernel: BaseOS repodata
# --------------------------------------------------------------------------- #

def _primary_href(repomd: ET.Element) -> str:
    for d in repomd.findall("r:data", REPO_NS):
        if d.get("type") == "primary":
            loc = d.find("r:location", REPO_NS)
            if loc is not None and loc.get("href"):
                return loc.get("href")  # type: ignore[return-value]
    raise RuntimeError("primary data block not found in repomd.xml")


def latest_released_kernel() -> Nevra:
    repomd_raw = http_get(f"{REPO_BASE}/repodata/repomd.xml")
    href = _primary_href(ET.fromstring(repomd_raw))
    primary_gz = http_get(f"{REPO_BASE}/{href}")
    xml_bytes = gzip.decompress(primary_gz)

    pkg_tag = f"{{{REPO_NS['c']}}}package"
    name_tag = f"{{{REPO_NS['c']}}}name"
    arch_tag = f"{{{REPO_NS['c']}}}arch"
    ver_tag = f"{{{REPO_NS['c']}}}version"
    time_tag = f"{{{REPO_NS['c']}}}time"

    best: Nevra | None = None
    best_buildtime = -1

    for _ev, elem in ET.iterparse(io.BytesIO(xml_bytes), events=("end",)):
        if elem.tag != pkg_tag:
            continue
        name_el = elem.find(name_tag)
        arch_el = elem.find(arch_tag)
        if (name_el is None or name_el.text != "kernel"
                or arch_el is None or arch_el.text != "x86_64"):
            elem.clear()
            continue
        ver = elem.find(ver_tag)
        bt = elem.find(time_tag)
        buildtime = int(bt.get("build", "0")) if bt is not None else 0
        nevra = Nevra(
            name="kernel",
            epoch=ver.get("epoch", "0") if ver is not None else "0",
            version=ver.get("ver", "") if ver is not None else "",
            release=ver.get("rel", "") if ver is not None else "",
        )
        if buildtime > best_buildtime:
            best, best_buildtime = nevra, buildtime
        elem.clear()

    if best is None:
        raise RuntimeError("no kernel package found in BaseOS primary metadata")
    return best


# --------------------------------------------------------------------------- #
# Koji
# --------------------------------------------------------------------------- #

def _koji() -> xmlrpc.client.ServerProxy:
    return xmlrpc.client.ServerProxy(KOJI_URL, allow_none=True)


def latest_tagged_kernel(tag: str) -> Nevra | None:
    builds = _koji().getLatestBuilds(tag, None, "kernel")
    if not builds:
        return None
    b = builds[0]
    return Nevra(
        name=b["name"],
        epoch=str(b.get("epoch") or "0"),
        version=b["version"],
        release=b["release"],
    )


def kernel_changelog(nvr: str) -> list[tuple[str, str, int]]:
    """Return [(header, body, epoch_seconds), ...] newest first, from Koji SRPM headers."""
    s = _koji()
    build = s.getBuild(nvr)
    if not build:
        raise RuntimeError(f"Koji has no build {nvr}")
    srpms = [r for r in s.listRPMs(build["build_id"]) if r["arch"] == "src"]
    if not srpms:
        raise RuntimeError(f"build {nvr} has no SRPM listed")
    hdrs = s.getRPMHeaders(srpms[0]["id"], ["changelogtime", "changelogname", "changelogtext"])
    names = hdrs.get("CHANGELOGNAME") or []
    texts = hdrs.get("CHANGELOGTEXT") or []
    times = hdrs.get("CHANGELOGTIME") or []
    return list(zip(names, texts, times))


def cves_in_changelog(entries: list[tuple[str, str, int]]) -> set[str]:
    found: set[str] = set()
    for _name, body, _t in entries:
        found.update(CVE_RE.findall(body))
    return found


def cve_evidence(entries: list[tuple[str, str, int]], cve: str) -> str | None:
    """First line in the changelog that mentions the CVE, if any."""
    for _name, body, _t in entries:
        if cve in body:
            for line in body.splitlines():
                if cve in line:
                    return line.strip()
    return None


# --------------------------------------------------------------------------- #
# Red Hat Security Data
# --------------------------------------------------------------------------- #

def redhat_cve(cve: str) -> dict:
    return json.loads(http_get(REDHAT_CVE_URL.format(cve=cve)))


def rhel9_kernel_fix(cve_data: dict) -> dict | None:
    for rel in cve_data.get("affected_release", []):
        prod = rel.get("product_name", "")
        pkg = rel.get("package", "")
        if "Red Hat Enterprise Linux 9" in prod and pkg.startswith(("kernel-0:", "kernel-")):
            return rel
    return None


# --------------------------------------------------------------------------- #
# Verdict
# --------------------------------------------------------------------------- #

def decide_verdict(version_patched: bool | None,
                   changelog_evidence: str | None) -> tuple[str, str]:
    """Return (verdict, reason) for a single (source, CVE) pair.

    `version_patched` is True/False if Red Hat has published a RHEL 9 fixed
    NEVRA we could compare against, None otherwise.
    `changelog_evidence` is the changelog line that mentions the CVE, or None.

    Verdict is "patched" iff version comparison says we're at or past the
    fix, or the changelog mentions the CVE. Otherwise "not_patched" — which
    includes the "no Red Hat record and no changelog mention" case, since
    the actionable interpretation is "no kernel covers this yet".
    """
    if version_patched is True:
        return "patched", "kernel >= RHEL9 fix"
    if changelog_evidence:
        return "patched", "backport in changelog"
    if version_patched is False:
        return "not_patched", "kernel older than RHEL9 fix"
    return "not_patched", "no fix in changelog or Red Hat data"


# --------------------------------------------------------------------------- #
# Source dispatch
# --------------------------------------------------------------------------- #

def resolve_source(source: str) -> Nevra | None:
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
            n = resolve_source(src)
            out[src] = str(n) if n else None
        except Exception as e:
            out[src] = f"<error: {e}>"
    if args.json:
        print(json.dumps(out, indent=2))
    else:
        w = max(len(s) for s in SOURCES)
        for s in SOURCES:
            print(f"{s.ljust(w)}  {out[s] or '(none)'}")
    return 0


def cmd_check(args) -> int:
    findings: list[dict] = []
    for raw in args.cve:
        cve = raw.upper()
        if not CVE_RE.fullmatch(cve):
            print(f"warning: skipping {raw!r} — not a valid CVE ID", file=sys.stderr)
            continue
        result: dict = {"cve": cve, "sources": {}, "redhat": None}

        rh_fix_evr: tuple[str, str, str] | None = None
        try:
            data = redhat_cve(cve)
            fix = rhel9_kernel_fix(data)
            rh_fix_evr = parse_evr(fix["package"]) if fix and fix.get("package") else None
            result["redhat"] = {
                "severity": data.get("threat_severity"),
                "public_date": data.get("public_date"),
                "rhel9_fix": fix.get("package") if fix else None,
                "rhel9_release_date": fix.get("release_date") if fix else None,
            }
        except Exception as e:
            result["redhat"] = {"error": str(e)}

        for src in SOURCES:
            try:
                nevra = resolve_source(src)
            except Exception as e:
                result["sources"][src] = {"error": f"resolve: {e}"}
                continue
            if nevra is None:
                result["sources"][src] = {"nvr": None, "verdict": None}
                continue

            entry: dict = {"nvr": nevra.nvr}
            if rh_fix_evr is not None:
                our_evr = (nevra.epoch, nevra.version, nevra.release)
                cmp = evr_compare(our_evr, rh_fix_evr)
                entry["version_patched"] = cmp >= 0
                entry["version_cmp"] = cmp
            else:
                entry["version_patched"] = None

            try:
                entries = kernel_changelog(nevra.nvr)
                entry["changelog_evidence"] = cve_evidence(entries, cve)
            except Exception as e:
                entry["changelog_error"] = str(e)
                entry["changelog_evidence"] = None

            entry["verdict"], entry["reason"] = decide_verdict(
                entry["version_patched"], entry["changelog_evidence"]
            )
            result["sources"][src] = entry

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
                public = (rh.get("public_date") or "?")[:10]
                print(f"  Severity:    {rh.get('severity') or '?'}")
                print(f"  Public date: {public}")
                fix = rh.get("rhel9_fix")
                if fix:
                    rel = (rh.get("rhel9_release_date") or "?")[:10]
                    print(f"  RHEL9 fix:   {fix}  (released {rel})")
                else:
                    print(f"  RHEL9 fix:   (not yet listed by Red Hat)")
            print()
            for src in SOURCES:
                s = f["sources"].get(src, {})
                if "error" in s:
                    print(f"  {src:10s} ERROR: {s['error']}")
                    continue
                if s.get("nvr") is None:
                    print(f"  {src:10s} (no kernel found)")
                    continue
                label = "PATCHED" if s["verdict"] == "patched" else "NOT PATCHED"
                reason = s.get("reason", "")
                print(f"  {src:10s} {label:12s} {reason}")
                ev = s.get("changelog_evidence")
                if ev:
                    print(f"             evidence: {ev}")
            print()

    any_not_patched = any(
        s.get("verdict") == "not_patched"
        for f in findings for s in f["sources"].values()
        if isinstance(s, dict)
    )
    return 1 if any_not_patched else 0


def cmd_changelog(args) -> int:
    nevra = resolve_source(args.source)
    if nevra is None:
        print(f"no kernel found for source {args.source}", file=sys.stderr)
        return 2
    entries = kernel_changelog(nevra.nvr)
    print(f"# {nevra} — {len(entries)} changelog entries")
    print()
    shown = entries[: args.limit] if args.limit else entries
    for name, body, _t in shown:
        print(f"* {name}")
        print(body)
        print()
    return 0


def cmd_cves(args) -> int:
    nevra = resolve_source(args.source)
    if nevra is None:
        print(f"no kernel found for source {args.source}", file=sys.stderr)
        return 2
    entries = kernel_changelog(nevra.nvr)
    cves = sorted(cves_in_changelog(entries), reverse=True)
    if args.json:
        print(json.dumps({"source": args.source, "nvr": nevra.nvr, "cves": cves}, indent=2))
    else:
        print(f"# {len(cves)} CVEs referenced in {nevra} changelog")
        for c in cves:
            print(c)
    return 0


# --------------------------------------------------------------------------- #
# Entrypoint
# --------------------------------------------------------------------------- #

def main(argv: list[str] | None = None) -> int:
    common = argparse.ArgumentParser(add_help=False)
    common.add_argument("--json", action="store_true", help="machine-readable output")

    p = argparse.ArgumentParser(
        prog="c9s-kernel",
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter,
        parents=[common],
    )

    sub = p.add_subparsers(dest="cmd", required=True)

    sp = sub.add_parser("latest", parents=[common],
                        help="show newest kernel across released/pending/gate")
    sp.set_defaults(func=cmd_latest)

    sp = sub.add_parser("check", parents=[common],
                        help="check whether CVEs are mentioned in each source's changelog")
    sp.add_argument("cve", nargs="+", help="one or more CVE IDs (e.g. CVE-2024-1086)")
    sp.set_defaults(func=cmd_check)

    sp = sub.add_parser("changelog", parents=[common], help="dump kernel changelog for a source")
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
