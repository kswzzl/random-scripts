# c9s-kernel

A small CLI for tracking CentOS Stream 9 kernels and figuring out whether a given CVE has actually been patched in one of them yet.

## Why this exists

When a kernel CVE drops, the question I actually want answered is "is there a CentOS Stream 9 kernel I can install that fixes this?" versus "what's the latest kernel version?". This wraps three data sources so you can ask the real question directly.

## How it works

There are three places a CentOS Stream 9 kernel can live, in increasing order of staleness:

- **pending** — Koji `c9s-pending` tag. Newest builds, signed but not yet in a compose. This is the earliest place a CVE backport surfaces.
- **gate** — Koji `c9s-gate` tag. Builds that have passed gating but haven't hit BaseOS yet.
- **released** — what's actually published in BaseOS at `mirror.stream.centos.org`. This is what `dnf install kernel` would pull.

All comparisons are Stream-vs-Stream. We deliberately don't compare against RHEL fixed NEVRAs — the two distributions use different release-numbering schemes (Stream is `697.el9`, RHEL is `427.13.1.el9_4`), so cross-distribution version comparison gives unreliable answers.

For each source, the verdict comes from up to three signals, in priority order:

1. **The source's own changelog mentions the CVE.** Definitive PATCHED. A build's SRPM changelog is exactly the list of patches in that build — if the CVE ID appears, the fix is there. Red Hat writes CVE IDs directly into the entry for the patch, e.g. `... {CVE-2025-68724}`.

2. **Some other source mentions the CVE, naming the introducer build.** Each kernel changelog entry is headed by the build it landed in, e.g. `[5.14.0-700.el9]`. If pending's changelog mentions CVE-X in the entry for build 700, the fix landed in 700. Compare each source's release against 700: at-or-past → PATCHED, older → NOT PATCHED. This comparison is Stream-vs-Stream and reliable.

3. **Nobody has evidence.** Fall back to a public-date heuristic. Red Hat publishes a `public_date` per CVE; the SRPM changelog has timestamps on each entry. If the CVE went public after our oldest visible changelog entry, we'd have seen the fix if it had landed → NOT PATCHED. If the CVE predates our window, the fix may have rolled off and we genuinely can't tell from this build alone → UNKNOWN.

UNKNOWN is reserved for the third case — when the visible changelog history doesn't reach back far enough to cover the CVE. For old CVEs that need a definitive answer, dump a longer changelog with `c9s_kernel.py changelog` and grep manually, or rely on the fact that Stream lifecycle generally means an old CVE has long since been fixed.

## Usage

```
python3 c9s_kernel.py latest                    # show released / gate / pending NVRs
python3 c9s_kernel.py check CVE-2024-1086       # verdict per source
python3 c9s_kernel.py check CVE-... CVE-... ... # multiple at once
python3 c9s_kernel.py changelog --source pending [--limit 5]
python3 c9s_kernel.py cves --source pending     # every CVE referenced in that kernel
```

`check` exits 1 if any source comes back NOT PATCHED, so it slots into a cron job or CI alert without extra parsing. Add `--json` to any subcommand for machine-readable output.

## Tests

There's a pytest suite covering the pure-logic pieces — RPM version comparison, NEVRA parsing, changelog scanning, and verdict calculation. Network-touching code paths aren't covered (those are exercised by running the CLI itself).

```
pip install pytest
pytest
```

## Limitations

- x86_64 only. The Koji side is arch-independent, so adding aarch64 is mostly a matter of pointing the repodata fetcher at a different mirror path.
- "PATCHED" means the kernel package contains the fix. It does not mean you've installed it on a host. To check a running machine, compare `uname -r` against the `released` NVR.
- For very old CVEs whose fixes predate every visible changelog window, the verdict is UNKNOWN. The tool intentionally doesn't walk Koji history to find a definitive answer for those — if you need one, dump the changelog with `python3 c9s_kernel.py changelog --source pending` and grep manually.

## Glossary

**Koji** is Red Hat's RPM build system — the upstream pipeline where Fedora, CentOS Stream, and RHEL packages get built from source, signed, and tagged. Builds move through a series of named tags as they progress: `c9s-pending` holds the freshest signed builds, `c9s-gate` holds builds that have passed gating, and so on. Koji exposes an XML-RPC API at `kojihub.stream.centos.org/kojihub` that lets you query builds, tags, and RPM headers without ever needing a CentOS host. That's where this tool gets the pending and gate kernel info.

**NEVRA** is the full identifier for an RPM package — Name, Epoch, Version, Release, Architecture. Drop the arch and it's NEVR; drop the epoch too and it's NVR. Example:

```
kernel-0:5.14.0-697.el9.x86_64
       │ │      │       │
       │ │      │       └── Architecture (x86_64)
       │ │      └────────── Release   (RPM packaging revision; `el9` = dist tag)
       │ └───────────────── Version   (upstream source version)
       └─────────────────── Epoch     (rarely used; overrides version comparison)
```

The version is whatever upstream tagged the source as. The release increments every time the package gets rebuilt with new patches — so for the kernel, the `el9` release number (e.g. `697`) is the actual signal of "how many patches have been applied since the upstream version". The dist tag (`el9`, `el9_4`) marks which distribution and minor release the build targets. Epoch is a rarely-used override that lets a maintainer force a package to be considered newer than another even if the version string would say otherwise; the kernel doesn't use it (epoch is always 0).

When Red Hat says CVE-X is fixed in `kernel-0:5.14.0-427.13.1.el9_4`, that's the NEVRA. To know whether your kernel includes the fix, you compare your NEVRA against that one using RPM's version-comparison rules — which is what the version-comparison signal above does.
