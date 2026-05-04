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

Cache:
    ~/.cache/c9s-kernel/  (1h TTL; --ttl to override, --no-cache to bypass)
    SRPM changelogs are cached for 7d since they're immutable per NVR.
"""

from __future__ import annotations

import argparse
import gzip
import hashlib
import io
import json
import os
import re
import sys
import time
import urllib.request
import xml.etree.ElementTree as ET
import xmlrpc.client
from dataclasses import dataclass
from pathlib import Path

REPO_BASE = "https://mirror.stream.centos.org/9-stream/BaseOS/x86_64/os"
KOJI_URL = "https://kojihub.stream.centos.org/kojihub"
REDHAT_CVE_URL = "https://access.redhat.com/hydra/rest/securitydata/cve/{cve}.json"

CACHE_DIR = Path(os.environ.get("XDG_CACHE_HOME", str(Path.home() / ".cache"))) / "c9s-kernel"
DEFAULT_TTL = 3600
CHANGELOG_TTL = 7 * 24 * 3600
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

_ALNUM_RE = re.compile(r"([A-Za-z]+|[0-9]+)")


def rpmvercmp(a: str, b: str) -> int:
    """Compare two RPM version/release strings. Returns -1 / 0 / 1."""
    if a == b:
        return 0
    i = j = 0
    while i < len(a) and j < len(b):
        # ~ sorts before anything (including end-of-string)
        if a[i] == "~" or b[j] == "~":
            if a[i] != "~":
                return 1
            if b[j] != "~":
                return -1
            i += 1
            j += 1
            continue
        # ^ sorts after end-of-string but before anything else
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
        # Skip separators
        if not a[i].isalnum():
            i += 1
            continue
        if not b[j].isalnum():
            j += 1
            continue
        # Extract a segment from each side
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
        # Numeric beats alpha
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
    # One side exhausted
    if i == len(a) and j == len(b):
        return 0
    # Trailing ~ on whichever side still has content makes it older
    rem = a[i:] if i < len(a) else b[j:]
    if rem.startswith("~"):
        return -1 if i < len(a) else 1
    return 1 if i < len(a) else -1


def evr_compare(a: tuple[str, str, str], b: tuple[str, str, str]) -> int:
    """Compare (epoch, version, release) tuples. Missing epoch defaults to 0."""
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
    # Strip leading 'name-' (everything up to and including the first '-')
    if "-" not in s:
        return None
    _name, rest = s.split("-", 1)
    # rest is now [epoch:]version-release
    epoch = "0"
    if ":" in rest.split("-", 1)[0]:
        epoch, rest = rest.split(":", 1)
    if "-" not in rest:
        return None
    version, release = rest.rsplit("-", 1)
    return epoch, version, release


# --------------------------------------------------------------------------- #
# Cache
# --------------------------------------------------------------------------- #

def _cache_path(key: str) -> Path:
    h = hashlib.sha256(key.encode()).hexdigest()[:24]
    return CACHE_DIR / f"{h}.bin"


def cache_get(key: str, ttl: int) -> bytes | None:
    p = _cache_path(key)
    if not p.exists():
        return None
    if ttl > 0 and time.time() - p.stat().st_mtime > ttl:
        return None
    return p.read_bytes()


def cache_put(key: str, data: bytes) -> None:
    CACHE_DIR.mkdir(parents=True, exist_ok=True)
    p = _cache_path(key)
    tmp = p.with_suffix(".tmp")
    tmp.write_bytes(data)
    tmp.replace(p)


# --------------------------------------------------------------------------- #
# HTTP
# --------------------------------------------------------------------------- #

def http_get(url: str, ttl: int = DEFAULT_TTL, no_cache: bool = False) -> bytes:
    if not no_cache:
        cached = cache_get(url, ttl)
        if cached is not None:
            return cached
    req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
    with urllib.request.urlopen(req, timeout=60) as resp:
        data = resp.read()
    cache_put(url, data)
    return data


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


def latest_released_kernel(no_cache: bool, ttl: int) -> Nevra:
    repomd_raw = http_get(f"{REPO_BASE}/repodata/repomd.xml", ttl=ttl, no_cache=no_cache)
    href = _primary_href(ET.fromstring(repomd_raw))
    primary_gz = http_get(f"{REPO_BASE}/{href}", ttl=ttl, no_cache=no_cache)
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


def kernel_changelog(nvr: str, no_cache: bool) -> list[tuple[str, str, int]]:
    """Return [(header, body, epoch_seconds), ...] newest first, from Koji SRPM headers."""
    cache_key = f"changelog::{nvr}"
    if not no_cache:
        cached = cache_get(cache_key, CHANGELOG_TTL)
        if cached is not None:
            return [tuple(e) for e in json.loads(cached)]  # type: ignore[misc]

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
    entries = list(zip(names, texts, times))
    cache_put(cache_key, json.dumps(entries).encode())
    return entries


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

def redhat_cve(cve: str, no_cache: bool, ttl: int) -> dict:
    raw = http_get(REDHAT_CVE_URL.format(cve=cve), ttl=ttl, no_cache=no_cache)
    return json.loads(raw)


def rhel9_kernel_fix(cve_data: dict) -> dict | None:
    for rel in cve_data.get("affected_release", []):
        prod = rel.get("product_name", "")
        pkg = rel.get("package", "")
        if "Red Hat Enterprise Linux 9" in prod and pkg.startswith(("kernel-0:", "kernel-")):
            return rel
    return None


# --------------------------------------------------------------------------- #
# Source dispatch
# --------------------------------------------------------------------------- #

def resolve_source(source: str, no_cache: bool, ttl: int) -> Nevra | None:
    if source == "released":
        return latest_released_kernel(no_cache, ttl)
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
            n = resolve_source(src, args.no_cache, args.ttl)
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

        # Pull Red Hat first so we know the fixed NEVRA before per-source loop
        rh_fix_evr: tuple[str, str, str] | None = None
        try:
            data = redhat_cve(cve, no_cache=args.no_cache, ttl=args.ttl)
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
                nevra = resolve_source(src, args.no_cache, args.ttl)
            except Exception as e:
                result["sources"][src] = {"error": f"resolve: {e}"}
                continue
            if nevra is None:
                result["sources"][src] = {"nvr": None, "verdict": None}
                continue

            entry: dict = {"nvr": nevra.nvr}
            # Version verdict via Red Hat fixed NEVRA
            if rh_fix_evr is not None:
                our_evr = (nevra.epoch, nevra.version, nevra.release)
                cmp = evr_compare(our_evr, rh_fix_evr)
                entry["version_patched"] = cmp >= 0
                entry["version_cmp"] = cmp
            else:
                entry["version_patched"] = None  # Red Hat didn't list a RHEL 9 fix

            # Changelog evidence
            try:
                entries = kernel_changelog(nevra.nvr, no_cache=args.no_cache)
                entry["changelog_evidence"] = cve_evidence(entries, cve)
            except Exception as e:
                entry["changelog_error"] = str(e)
                entry["changelog_evidence"] = None

            # Verdict: PATCHED iff version comparison says so OR the changelog
            # backports the CVE. Otherwise NOT PATCHED — including the case
            # where Red Hat hasn't published a RHEL 9 fix and the changelog
            # doesn't mention the CVE, which is the actionable "no kernel
            # covers this yet" state.
            if entry["version_patched"] is True or entry["changelog_evidence"]:
                entry["verdict"] = "patched"
                if entry["version_patched"] is True:
                    entry["reason"] = "kernel >= RHEL9 fix"
                else:
                    entry["reason"] = "backport in changelog"
            else:
                entry["verdict"] = "not_patched"
                if entry["version_patched"] is False:
                    entry["reason"] = "kernel older than RHEL9 fix"
                else:
                    entry["reason"] = "no fix in changelog or Red Hat data"

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
    nevra = resolve_source(args.source, args.no_cache, args.ttl)
    if nevra is None:
        print(f"no kernel found for source {args.source}", file=sys.stderr)
        return 2
    entries = kernel_changelog(nevra.nvr, no_cache=args.no_cache)
    print(f"# {nevra} — {len(entries)} changelog entries")
    print()
    shown = entries[: args.limit] if args.limit else entries
    for name, body, _t in shown:
        print(f"* {name}")
        print(body)
        print()
    return 0


def cmd_cves(args) -> int:
    nevra = resolve_source(args.source, args.no_cache, args.ttl)
    if nevra is None:
        print(f"no kernel found for source {args.source}", file=sys.stderr)
        return 2
    entries = kernel_changelog(nevra.nvr, no_cache=args.no_cache)
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
    common.add_argument("--ttl", type=int, default=DEFAULT_TTL,
                        help=f"cache TTL in seconds (default {DEFAULT_TTL})")
    common.add_argument("--no-cache", action="store_true", help="bypass and rewrite cache")
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
