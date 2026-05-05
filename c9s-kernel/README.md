# c9s-kernel

Tool for tracking CentOS Stream 9 kernels and checking whether a given CVE has been patched in one of them.

When a kernel CVE drops, the question I want answered is "is there a Stream 9 kernel I can install that fixes this?", not "what's the latest kernel version?". Those are different questions. This wraps a few data sources so I can ask the real one.

## What a CentOS kernel version actually is

A version like `kernel-5.14.0-700.el9` packs three things into one string:

- `5.14.0` is the upstream Linux version
- `700` is the release number. Red Hat's internal counter of how many times they've rebuilt this kernel with new patches. It only goes up.
- `el9` is the dist tag. Says "this is for the Enterprise Linux 9 family".

The upstream version barely changes. Red Hat picked `5.14.0` at the start of EL9 and they're sticking with it for the entire EL9 lifecycle. Instead of rebasing onto newer upstream kernels they backport fixes into this old one.

## Stream isn't the same as RHEL

CentOS Stream is upstream of RHEL. Patches flow:

```
upstream Linux → CentOS Stream 9 → RHEL 9
```

Stream gets fixes first. They sit there a while, get tested, then flow into RHEL as official errata. When a CVE drops, the patch usually lands in Stream a few days or weeks before there's a RHEL advisory.

Both distros use the same kernel source code (one Git repo). But the packages, the actual RPMs you install, are different builds with different release strings. Stream uses simple counters like `700.el9`. RHEL uses strings tied to minor versions like `427.13.1.el9_4`. The two are in totally separate numbering namespaces. Stream's `700` and RHEL's `427.13.1` aren't on the same scale at all.

That's why this tool is Stream-only. If you tried to compare across distros, the numbers would line up by coincidence sometimes and lie to you the rest of the time.

## Three places a Stream kernel can live

"What's the latest Stream 9 kernel?" has three answers depending on how fresh you want:

1. `pending`. Freshly signed builds sitting in Red Hat's build system, not yet in any published repo. The earliest place a CVE backport will show up.
2. `gate`. Builds that have passed automated testing. A bit older than pending, a bit newer than released.
3. `released`. What's actually published in the BaseOS repo. This is what `dnf install kernel` would pull onto a real server.

To answer those, the tool talks to Koji (Red Hat's build system). It asks what's in the pending and gate tags, and reads the BaseOS repo metadata for what's released. That's what the `latest` subcommand reports.

## What we're actually trying to answer

When a CVE drops you want to know: is there a Stream 9 kernel I can install that has the fix?

Two pieces of evidence to work with:

First, the kernel's changelog. Every Stream kernel package ships with a build log: a list of patches added in each build. When Red Hat backports a CVE fix they write the CVE ID right into the changelog line, like `... {CVE-2025-68724}`. So if you see the CVE in build 700's changelog, build 700 has the fix. Definitive.

The catch is that the changelog only keeps the last dozen or so entries. Older patches roll off. A CVE patched a year ago might not appear in a current build's changelog even though the fix is absolutely still in the kernel.

Second, Red Hat's CVE database. A JSON record per CVE. Severity, public date, that sort of thing. Useful as metadata. Red Hat also lists "this CVE is fixed in package X", but X is a RHEL package, which we already said we can't compare against Stream. So we ignore that field and only pull severity and date out.

## How the verdict gets made

For each source, the tool tries three signals in priority order.

First, does the source's own changelog mention the CVE? If yes, we're done. PATCHED.

Second, does any other source's changelog mention it? If yes, we can pull the introducer build out of the entry. Every changelog entry is headed by the build it landed in, like `[5.14.0-700.el9]`. So if pending's changelog says the CVE was fixed in `[5.14.0-700.el9]`, the fix went in at build 700. Now compare each source's release number against 700:

- gate is on `697`. 697 < 700, so the fix is in a build newer than gate has. NOT PATCHED.
- released is on `700`. 700 >= 700, so it has the fix. PATCHED.

This works because we're comparing Stream releases to Stream releases. Same numbering scheme, real apples-to-apples comparison.

Third, if nobody has evidence anywhere, fall back to a date check:

- If the CVE went public after our oldest visible changelog entry, we'd have seen the fix if Red Hat had backported it. NOT PATCHED.
- If the CVE went public before our oldest entry, the fix may exist but has rolled off our window. UNKNOWN. Can't tell from this build alone.

## What the verdicts mean

- `PATCHED`: direct evidence the fix is in this build.
- `NOT PATCHED`: direct evidence the fix is not in this build. A newer build has it, ours doesn't.
- `UNKNOWN`: we can't tell. Usually means the CVE is old enough that the relevant changelog entry has scrolled off and no current build has the CVE in its visible history. In practice an old CVE on a current Stream kernel is almost certainly patched, but the tool won't claim that without evidence.

The `check` subcommand exits 1 if any source is NOT PATCHED. Drop it in a cron job and you'll only get woken up when a CVE actually lacks coverage in shipping kernels.

## Usage

```
python3 c9s_kernel.py latest                    # show released / gate / pending NVRs
python3 c9s_kernel.py check CVE-2024-1086       # verdict per source
python3 c9s_kernel.py check CVE-... CVE-... ... # multiple at once
python3 c9s_kernel.py changelog --source pending [--limit 5]
python3 c9s_kernel.py cves --source pending     # every CVE referenced in that kernel
```

Add `--json` to any subcommand for machine-readable output.

## Tests

There's a pytest suite covering the pure-logic pieces: RPM version comparison, changelog scanning, introducer parsing, and verdict calculation. The network-touching code paths aren't covered (those get exercised by running the CLI).

```
pip install pytest
pytest
```

## Limitations

- x86_64 only. The Koji side is arch-independent, so adding aarch64 is mostly a matter of pointing the repodata fetcher at a different mirror path.
- PATCHED means the kernel package contains the fix. It doesn't mean you've installed it on a host. To check a running machine, compare `uname -r` against the released NVR.
- For very old CVEs whose fixes predate every visible changelog window, the verdict is UNKNOWN. The tool intentionally doesn't walk Koji history to find a definitive answer. If you need one, dump the changelog with `python3 c9s_kernel.py changelog --source pending` and grep manually.
