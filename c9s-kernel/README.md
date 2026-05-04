# c9s-kernel

A small CLI for tracking CentOS Stream 9 kernels and figuring out whether a
given CVE has actually been patched in one of them yet.

## Why this exists

When a kernel CVE drops, the question I actually want answered is "is there a CentOS Stream 9 kernel I can install that fixes this?" versus "what's the latest kernel version?". This wraps three data sources so you can ask the real question directly.

## How it works

There are three places a CentOS Stream 9 kernel can live, in increasing order of staleness:

- **pending** — Koji `c9s-pending` tag. Newest builds, signed but not yet in a compose. This is the earliest place a CVE backport surfaces.
- **gate** — Koji `c9s-gate` tag. Builds that have passed gating but haven't hit BaseOS yet.
- **released** — what's actually published in BaseOS at `mirror.stream.centos.org`. This is what `dnf install kernel` would pull.

For each one, the tool decides PATCHED vs NOT PATCHED using two independent signals:

1. **Version comparison against Red Hat's advisory.** Red Hat's security data API publishes a fixed NEVRA per CVE for RHEL 9 (e.g.
   `kernel-0:5.14.0-427.13.1.el9_4`). If our kernel's release is greater than or equal to that NEVRA, it's patched. The RPM version comparison
   (`rpmvercmp`) is built in, so you don't need the `rpm` binary on the machine running this.

2. **Changelog grep.** The kernel SRPM changelog is pulled from Koji and searched for the CVE ID. Red Hat writes the CVE ID directly into the
   changelog entry for the patch, e.g. `... {CVE-2025-68724}`. This catches CVEs that haven't been added to Red Hat's security data API yet, which is the common case for fresh disclosures. If either signal says yes, the verdict is PATCHED. Otherwise NOT PATCHED.

The two signals complement each other: version comparison handles old CVEs whose patches have rolled off the visible changelog window (the SRPM
changelog only carries roughly the last dozen entries), and changelog grep handles brand-new CVEs that Red Hat's API hasn't indexed yet.

## Usage

```
c9s-kernel latest                    # show released / gate / pending NVRs
c9s-kernel check CVE-2024-1086       # verdict per source
c9s-kernel check CVE-... CVE-... ... # multiple at once
c9s-kernel changelog --source pending [--limit 5]
c9s-kernel cves --source pending     # every CVE referenced in that kernel
```

`check` exits 1 if any source comes back NOT PATCHED, so it slots into a cron job or CI alert without extra parsing. Add `--json` to any subcommand for machine-readable output.

## Caching

HTTP fetches and Koji queries get cached under `~/.cache/c9s-kernel/`. Default TTL is one hour. SRPM changelogs are cached for seven days since they're immutable per NVR. `--no-cache` bypasses and overwrites.

## Limitations

- x86_64 only. The Koji side is arch-independent, so adding aarch64 is mostly a matter of pointing the repodata fetcher at a different mirror path.
- The version-comparison signal trusts Red Hat's security data API as the canonical fixed NEVRA for RHEL 9. Stream-specific fixes that never made it into RHEL won't have a fixed NEVRA there, so you're relying on changelog grep alone for those.
- "PATCHED" means the kernel package contains the fix. It does not mean you've installed it on a host. To check a running machine, compare `uname -r` against the `released` NVR.

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
