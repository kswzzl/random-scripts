# c9s-kernel

A small CLI for tracking CentOS Stream 9 kernels and figuring out whether a given CVE has actually been patched in one of them.

When a kernel CVE drops, the question I actually want answered is "is there a Stream 9 kernel I can install that fixes this?" — not "what's the latest kernel version?". This wraps a few data sources so you can ask the real question directly.

## What a kernel version actually is

The Linux kernel is the bottom layer of the operating system — the thing that talks to your hardware. Every distribution ships its own kernel, even when they all started from the same upstream source code.

A version like `kernel-5.14.0-700.el9` packs three pieces of info into one string:

- **`5.14.0`** is the upstream version — what Linus Torvalds tagged in the upstream Git tree years ago.
- **`700`** is the *release number* — Red Hat's internal counter of how many times they've rebuilt this kernel with new patches. It only goes up.
- **`el9`** is the dist tag, meaning "this is for the Enterprise Linux 9 family".

In practice the upstream version barely changes. Red Hat picked `5.14.0` at the start of EL9 and they're sticking with it for the entire EL9 lifecycle — they backport fixes from newer upstream kernels into this old version rather than rebasing. So the *release number* is the thing that actually moves. Build 700 is newer than 697 is newer than 690. That's the meaningful axis.

## Stream isn't the same as RHEL

CentOS Stream is the *upstream* of RHEL. Patches flow in this direction:

```
upstream Linux → CentOS Stream 9 → RHEL 9
```

Stream gets fixes first. They sit there a while, get tested, then flow into RHEL as official errata. So when a CVE drops, the patch typically lands in Stream a few days or weeks before there's a RHEL advisory.

Both distros use the *same kernel source code* — one Git repo. But the *packages* (the actual RPMs you install) are different builds with different release strings. Stream uses simple counters like `700.el9`. RHEL uses minor-version-tied strings like `427.13.1.el9_4`. They're in totally different numbering namespaces. Comparing them numerically is like comparing the price of Apple stock to the price of an apple at the grocery store — the numbers exist but they don't mean the same thing.

That's why this tool is Stream-only. Cross-distribution release-number comparison would give wrong answers in subtle ways.

## Three places a Stream kernel can live

"What's the latest Stream 9 kernel?" actually has three different answers depending on how fresh you want:

1. **pending** — freshly signed builds sitting in Red Hat's build system, not yet in a published repo. This is the earliest place a CVE backport surfaces.
2. **gate** — builds that have passed automated testing. Slightly older than pending, slightly newer than released.
3. **released** — what's actually published in the BaseOS repo. This is what `dnf install kernel` pulls onto a real server.

The tool asks Red Hat's "Koji" build system (think: a factory floor with a public API) what's in the pending and gate tags, and reads the BaseOS repo metadata for what's released. That's what the `latest` subcommand reports.

## What we're actually trying to answer

When a CVE drops, the question is: *"Is there a Stream 9 kernel I can install that has the fix?"*

There are two pieces of evidence to work with:

**The kernel's changelog.** Every Stream kernel package ships with a build log — a list of "I added patches X, Y, Z in this build". When Red Hat backports a CVE fix, they write the CVE ID right into the changelog line, like `... {CVE-2025-68724}`. So if you see the CVE in build 700's changelog, build 700 has the fix. Definitive.

**The catch:** the changelog only carries roughly the last dozen entries. Older patches roll off. A CVE patched a year ago won't show up in a current build's changelog even though the fix is absolutely still in the kernel.

**Red Hat's CVE database.** A JSON record per CVE — severity, publication date, that kind of thing. Useful for metadata. Red Hat also says "this CVE is fixed in package X" but X is a RHEL package, which we already established we can't compare against Stream packages. So we ignore that field and only use the metadata.

## How the verdict gets made

For each of the three sources (released, pending, gate), the tool tries three signals in priority order:

**Signal 1 — the source's own changelog mentions the CVE.**
If build 700's changelog has the CVE in it, build 700 has the fix. → PATCHED. Done.

**Signal 2 — some *other* source's changelog mentions the CVE, naming the introducer build.**
Every changelog entry is headed by the build it landed in: `[5.14.0-700.el9]`. So if pending's changelog says the CVE was fixed in `[5.14.0-700.el9]`, we know the introducer build is 700. Now we can compare each source's release number against that:

- gate is on `697` → 697 < 700 → the fix is in a *newer* build than gate has → NOT PATCHED.
- released is on `700` → 700 ≥ 700 → has the fix → PATCHED.

This works because we're comparing Stream releases against Stream releases — same numbering scheme, real comparison.

**Signal 3 — nobody has evidence anywhere. Fall back to a date check.**

- If the CVE went public *after* our oldest visible changelog entry, we'd have seen the fix if it had landed → NOT PATCHED.
- If the CVE went public *before* our oldest entry, the fix may exist but has rolled off our window → UNKNOWN. Honest uncertainty.

## What the verdicts mean

- **PATCHED** — direct evidence the fix is in this build.
- **NOT PATCHED** — direct evidence the fix is *not* in this build (a newer build has it, and ours doesn't).
- **UNKNOWN** — we can't tell. Almost always because the CVE is old enough that the relevant changelog entry has scrolled off and no current build has the CVE in its visible history. For practical purposes an old CVE on a current Stream kernel is overwhelmingly likely to be patched, but the tool won't claim that without evidence.

The `check` subcommand exits with code 1 if any source is NOT PATCHED, so you can drop it in a cron job and only get woken up when a CVE actually lacks coverage in shipping kernels.

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

There's a pytest suite covering the pure-logic pieces — RPM version comparison, changelog scanning, introducer parsing, and the verdict calculation. Network-touching code paths aren't covered (those are exercised by running the CLI).

```
pip install pytest
pytest
```

## Limitations

- x86_64 only. The Koji side is arch-independent, so adding aarch64 is mostly a matter of pointing the repodata fetcher at a different mirror path.
- "PATCHED" means the kernel package contains the fix. It doesn't mean you've installed it on a host. To check a running machine, compare `uname -r` against the `released` NVR.
- For very old CVEs whose fixes predate every visible changelog window, the verdict is UNKNOWN. The tool intentionally doesn't walk Koji history to find a definitive answer for those — if you need one, dump the changelog with `python3 c9s_kernel.py changelog --source pending` and grep manually.
