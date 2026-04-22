---
name: security-audit
description: >-
  Security audit of a codebase. Five phases: (1) Semgrep scan using bundled
  offline rules, (2) triage semgrep findings by reading the actual source to
  classify true/false positives, (3) manual code review for bugs semgrep
  can't catch, (4) proof-of-bug via build + sanitizers + patch oracle for
  high-confidence findings, (5) final report consolidation + variant
  documentation. Each phase produces its own artifact. Phases can be run
  individually or together. Use when asked to audit code, find vulnerabilities,
  review security, do static analysis, or scan for bugs.
allowed-tools:
  - Agent
  - Bash
  - Read
  - Write
  - Glob
  - Grep
---

# Security Audit

Five-phase security review: automated scan → triage → manual code review → proof-of-bug → final report. Each phase builds on the previous one's output but can be run standalone. Each phase produces its own artifact — no phase edits another phase's output. Every finding carries an **evidence level** that tracks how far it has been validated.

## Evidence Levels

Every finding is tagged with an evidence level. Higher levels subsume lower ones — a `crash_reproduced` finding was necessarily `static_corroboration` first.

| Level | Meaning | Set by |
|---|---|---|
| `pattern_match` | A semgrep rule fired on this code | Phase 1 |
| `suspicion` | Looks wrong but data flow not fully traced | Phase 2 or 3 |
| `static_corroboration` | Data flow traced end-to-end in source; high confidence it's real | Phase 2 or 3 |
| `crash_reproduced` | A test/PoC triggers the bug under sanitizers or the project's own test harness | Phase 4 |
| `patch_validated` | A minimal fix was applied, the PoC re-ran, and the crash/error is gone — causal proof | Phase 4 |

Phase 4 attempts to promote `static_corroboration` findings to `crash_reproduced` or `patch_validated`. If it can't (build fails, no sanitizer available, language doesn't support it), the finding stays at `static_corroboration` with a note explaining what was attempted.

## Invocation Options

Detect these from the user's prompt — no formal parser.

| Phrase | Effect |
|---|---|
| `scan only`, `semgrep only`, `phase 1` | Run Phase 1 only |
| `triage only`, `phase 2` | Run Phase 2 only (requires prior Phase 1 output) |
| `review only`, `code review only`, `phase 3` | Run Phase 3 only (skip semgrep) |
| `triage`, `scan and triage`, `phases 1-2` | Run Phases 1 + 2 |
| `all bugs`, `all findings`, `no filter`, `include low`, `noisy` | Disable the default importance filter — report everything, including low-confidence and non-security findings |
| `include tests`, `audit tests` | Disable the default test-code exclusion (normally tests are ignored in all phases) |
| `include vendor`, `audit vendor`, `audit third-party` | Disable the default vendor/dep exclusion (normally vendored and third-party code is ignored) |
| `prove`, `proof`, `with proof`, `confirm bugs` | Run Phase 4 (proof-of-bug) after code review |
| `variants`, `variant analysis` | Run Phase 5 (final report + variant documentation) |
| `full pipeline`, `everything` | Run all five phases |
| `passes:N`, `N passes` | Set Phase 3 review pass count (default: 3) |
| `1 pass`, `single pass` | Run Phase 3 with only 1 review pass |
| `output to <dir>`, `into <dir>` | Custom output directory |

**Default (no flags):** Phases 1-3 only, **important-only mode** (severity + metadata filter on Phase 1, ≥80% confidence on Phase 3, high-value true positives only on Phase 2). Phase 3 runs **3 parallel review passes** by default. Output dir = `./security_audit_N` (auto-incremented). Phases 4-5 require explicit opt-in (`prove`, `variants`, or `full pipeline`).

**Important-only is the default across all phases** because noise defeats the point of the skill. Users who want the full unfiltered output must explicitly opt in with `all bugs` or equivalent.

## Output

All output goes to `$OUTPUT_DIR`. The skill mirrors the scanned directory's layout under `$OUTPUT_DIR` so that (a) multiple targets can share one output dir without collision, and (b) artifact paths stay meaningful when the repo moves.

**Mirror rule:** given TARGET, strip one of the well-known host prefixes (`/home/<user>/`, `/Users/<user>/`, `/workspace/`, `/root/`, `/tmp/`, `/var/www/`, `/opt/`) to produce `MIRRORED_SUBPATH`. If none match, fall back to `basename(TARGET)`. All artifacts for this scan go under `$OUTPUT_DIR/$MIRRORED_SUBPATH/`.

Examples:
- TARGET `/home/user/foo/bar` → `$OUTPUT_DIR/foo/bar/…`
- TARGET `/workspace/blah/baz` → `$OUTPUT_DIR/blah/baz/…`
- TARGET `/opt/projects/xyz` → `$OUTPUT_DIR/projects/xyz/…`

Per-target artifact layout:

```
$OUTPUT_DIR/<MIRRORED_SUBPATH>/
├── semgrep/              # Phase 1: raw semgrep JSON per ruleset
│   ├── <lang>-<rule>.json
│   ├── <lang>-<rule>-important.json
│   └── parse-failures.txt # files semgrep couldn't parse (Phase 1f)
├── triage.md             # Phase 2: finding-by-finding triage (merged if parallelized)
├── review.md             # Phase 3: merged code review findings (from N passes)
├── proof/                # Phase 4: proof-of-bug artifacts (if run)
│   ├── proof.md          # summary table + per-finding notes
│   ├── build.log         # build system detection + compile output
│   ├── poc_N.c           # PoC source for finding N
│   ├── poc_N_output.txt  # sanitizer/crash output
│   ├── patch_N.diff      # minimal fix for finding N
│   └── poc_N_patched_output.txt  # re-run after patch
└── report.md             # Phase 5: final consolidated report + variant patterns

# Transient (deleted during cleanup):
# orient.md              — Phase 3 system map, used to brief subagents
# review_pass_K.md       — Phase 3 per-pass results before merge
# triage_chunk_N.md      — Phase 2 per-chunk results before merge
```

**One artifact per phase.** Each phase writes its own file and never edits another phase's output. Phase 5 (`report.md`) is the authoritative final report — it synthesizes findings from phases 2-4, applies final evidence levels, and appends variant documentation. Earlier artifacts (`triage.md`, `review.md`, `proof/proof.md`) are working documents that remain frozen at the state they were written.

A short chat summary is printed at the end. The full report is in `report.md`.

---

## Phase 1: Semgrep Scan

Automated pattern-match scan using locally bundled rules. No network, no Pro, no telemetry.

### Hard Rules

1. **Always pass `--metrics=off`.**
2. **Only use rule directories under `{baseDir}/rules/`.** Never `--config p/...`, never `--config auto`, never a URL, never `git clone`.
3. **Never pass `--pro`.**
4. **Never install semgrep yourself.** If `command -v semgrep` fails, **error out immediately** with an install hint. Do not run `brew install`, `pipx install`, `pip install`, `apt`, `uv tool install`, or any equivalent — installing tooling is explicitly out of scope for this skill.
5. **Always ignore tests.** Test files, test directories, mocks, fixtures, benchmarks, and examples are excluded by default from every phase. Findings in test code are not reported. The default exclude list is in step 1d; users who explicitly want to audit tests must say `include tests`.
6. **Never silently skip a file.** If semgrep fails to parse a source file, record it in `parse-failures.txt` and surface it to the user. Phase 3 then prioritizes these files for manual review. No coverage gaps, anywhere.

### Steps

**1a. Resolve output dir, mirror path, and verify semgrep:**

```bash
# Output dir
if [ -n "$USER_SPECIFIED_DIR" ]; then
  OUTPUT_DIR="$USER_SPECIFIED_DIR"
else
  N=1; while [ -e "security_audit_$N" ]; do N=$((N+1)); done
  OUTPUT_DIR="security_audit_$N"
fi

# Mirror path under OUTPUT_DIR that reflects TARGET's location.
# Tries both the original path (as the user typed it) and the canonicalized
# path (pwd -P), because symlinks like /tmp → /private/tmp on macOS would
# otherwise hide all the meaningful prefixes. Regex prefixes handle any user
# for home dirs (not just the current $USER).
_mirror_path() {
  local orig="$1" canon stripped
  canon=$(cd "$orig" 2>/dev/null && pwd -P)
  [ -z "$canon" ] && canon="$orig"
  for t in "$orig" "$canon"; do
    # Strip the first matching prefix (order matters — most specific first).
    stripped=$(printf '%s' "$t" | sed -E 's,^/(home|Users)/[^/]+/,,; t out
      s,^/private/tmp/,,; t out
      s,^/tmp/,,; t out
      s,^/workspace/,,; t out
      s,^/root/,,; t out
      s,^/(private/)?var/www/,,; t out
      s,^/opt/,,; t out
      d
      :out')
    if [ -n "$stripped" ] && [ "$stripped" != "$t" ]; then
      echo "$stripped"
      return
    fi
  done
  basename "$canon"
}
MIRRORED_SUBPATH=$(_mirror_path "$TARGET")
MIRRORED="$OUTPUT_DIR/$MIRRORED_SUBPATH"
mkdir -p "$MIRRORED/semgrep"

# Semgrep must already be installed. NEVER attempt to install it.
if ! command -v semgrep >/dev/null; then
  cat >&2 <<'ERR'
ERROR: semgrep is not installed.
This skill will NOT install it for you. Install manually, then re-run:
  brew install semgrep          # macOS
  pipx install semgrep          # any OS with pipx
  python3 -m pip install semgrep
Then verify with: semgrep --version
ERR
  exit 1
fi
```

All subsequent steps write under `$MIRRORED` (e.g. `$MIRRORED/semgrep/*.json`, `$MIRRORED/triage.md`, `$MIRRORED/review.md`), not `$OUTPUT_DIR` directly.

**1b. Detect languages** using Glob (not Bash):

| Pattern | Language |
|---|---|
| `**/*.py` | Python |
| `**/*.go` | Go |
| `**/*.c`, `**/*.cc`, `**/*.cpp`, `**/*.cxx`, `**/*.h`, `**/*.hpp` | C / C++ |
| `**/*.js`, `**/*.jsx`, `**/*.mjs`, `**/*.cjs` | JavaScript |
| `**/*.ts`, `**/*.tsx` | TypeScript |
| `**/*.rs` | Rust |
| `**/*.cs`, `**/*.cshtml`, `**/*.razor` | C# |

Read `package.json`, `pyproject.toml`/`requirements.txt`, `go.mod`, `Cargo.toml` if present to detect frameworks.

**1c. Pick rule directories** from [references/rulesets.md](references/rulesets.md):

- Always include `semgrep-rules/generic` and `semgrep-rules/problem-based-packs` (cross-language, no `--include`).
- Add per-language primary + framework directories.
- If C or C++: add `0xdea-rules/rules/c`.

Resolve `{baseDir}` once to the absolute path of this skill.

**1d. Run semgrep in parallel** from a single Bash call:

```bash
TARGET=/abs/path/to/codebase
BASE=/abs/path/to/skill   # {baseDir}
# Default is important-only; set SEV=() if user explicitly requested "all bugs"
SEV=(--severity WARNING --severity ERROR)

# Default excludes. Always applied unless the user said `include tests` / `include vendor`.
# Test/benchmark/fixture directories and files — we never report findings in these.
EXCLUDES=(
  --exclude=tests --exclude=test --exclude=testing
  --exclude=__tests__ --exclude=__test__ --exclude=spec --exclude=specs
  --exclude=mocks --exclude=mock --exclude=fixtures --exclude=testdata
  --exclude=benchmarks --exclude=benchmark --exclude=bench
  --exclude=examples --exclude=example --exclude=samples
  --exclude='*_test.go' --exclude='*_test.py' --exclude='*_test.c' --exclude='*_test.cc' --exclude='*_test.cpp'
  --exclude='test_*.py' --exclude='test_*.c' --exclude='test_*.cpp'
  --exclude='*.test.js' --exclude='*.test.ts' --exclude='*.test.jsx' --exclude='*.test.tsx'
  --exclude='*.spec.js' --exclude='*.spec.ts'
  --exclude='*.tests.cs' --exclude='*Tests.cs'
  # Vendored / build / deps — noise that's not ours to audit
  --exclude=vendor --exclude=third_party --exclude=third-party --exclude=deps
  --exclude=node_modules --exclude=build --exclude='cmake-build*'
  --exclude=.git --exclude=.svn --exclude=.hg
  --exclude=target --exclude=dist --exclude=.next
)

run() {
  local dir="$1" name="$2"; shift 2
  semgrep --metrics=off --quiet "${SEV[@]}" "${EXCLUDES[@]}" "$@" \
    --config "$dir" --json -o "$MIRRORED/semgrep/$name.json" \
    "$TARGET" 2>"$MIRRORED/semgrep/$name.stderr"
}

run "$BASE/rules/semgrep-rules/python/lang"   python-lang   --include='*.py' &
run "$BASE/rules/semgrep-rules/c/lang"        c-lang        --include='*.c' --include='*.cpp' --include='*.h' --include='*.hpp' &
run "$BASE/rules/0xdea-rules/rules/c"         c-0xdea       &
run "$BASE/rules/semgrep-rules/generic"       generic       &
# ... one line per selected rule directory
wait
```

- `--include` only on language-specific directories. Cross-language dirs get none.
- `--severity` only accepts `INFO`, `WARNING`, `ERROR`. Not `LOW`/`MEDIUM`/`HIGH`/`CRITICAL` — those are JSON metadata, not CLI values.
- Each `--severity` flag must be a **separate shell token**, not one quoted string.
- With `--quiet`, real errors land in the JSON's `errors[]` array (not stderr). Check `jq '.errors' "$MIRRORED/semgrep/$name.json"` per-ruleset.
- Default `EXCLUDES` ignore tests, vendored code, and build artifacts. If user invoked with `include tests`, drop the test-related `--exclude` entries. `include vendor` drops the vendor/deps entries.

**1e. Post-filter (default; skip only if user asked for all bugs):**

```bash
for f in "$MIRRORED/semgrep"/*.json; do
  [[ "$f" == *-important.json ]] && continue
  jq '{
    results: [.results[] |
      ((.extra.metadata.category   // "security") | ascii_downcase) as $cat |
      ((.extra.metadata.confidence // "HIGH")     | ascii_upcase)   as $conf |
      ((.extra.metadata.impact     // "HIGH")     | ascii_upcase)   as $imp |
      select($cat == "security"
             and ($conf == "MEDIUM" or $conf == "HIGH")
             and ($imp  == "MEDIUM" or $imp  == "HIGH"))
    ],
    errors: .errors, paths: .paths
  }' "$f" > "${f%.json}-important.json"
done
```

**1f. Extract parse failures — always.** Semgrep silently skips files it cannot parse (common for modern C++, heavy templates, macro-heavy code). Coverage gaps must be made visible to the user AND routed to Phase 3.

```bash
# Collect unique files that any ruleset failed to parse.
# Semgrep uses several error types for this; catch all of them.
jq -r '.errors[]? | select(
         (.type // "") | test("(?i)syntax|parse|lexical|timeout|partial parse")
       ) | (.location.path // .path // empty)' \
  "$MIRRORED/semgrep"/*.json 2>/dev/null \
  | sort -u > "$MIRRORED/semgrep/parse-failures.txt"

PARSE_FAIL_COUNT=$(wc -l < "$MIRRORED/semgrep/parse-failures.txt" | tr -d ' ')
if [ "$PARSE_FAIL_COUNT" -gt 0 ]; then
  echo "WARNING: semgrep could not parse $PARSE_FAIL_COUNT file(s). See $MIRRORED/semgrep/parse-failures.txt"
  echo "These files will be prioritized for manual review in Phase 3."
fi
```

This file is a first-class input to Phase 3 — not just a diagnostic. Every listed file MUST be covered by Phase 3, no exceptions.

---

## Phase 2: Triage Semgrep Findings

Read each semgrep finding, look at the actual source code in context, and classify it.

### Parallelization

If there are **>15 findings** to triage, split them into chunks of ~8-10 and triage each chunk as a parallel subagent. Each subagent gets:
- The chunk of findings (rule ID, file, line range)
- The target directory path
- The four-bucket classification instructions below

Each subagent writes its results to a temp file (`$MIRRORED/triage_chunk_N.md`). After all complete, merge into `$MIRRORED/triage.md` and delete the chunk files.

For ≤15 findings, triage inline (no subagents needed).

### For each finding:

1. **Skip test findings.** If the finding's file path matches any test pattern (path contains `test`, `tests`, `spec`, `mocks`, `fixtures`, `testdata`, `benchmark`, `examples`; or basename matches `test_*`, `*_test.*`, `*.test.*`, `*.spec.*`), skip it silently. We don't report bugs in test code.
2. **Read the finding** from the JSON: rule ID, message, file path, line range.
3. **Read the source** at that location (use Read with enough surrounding context — typically ±20 lines).
4. **Classify into one of four buckets.** Every finding lands in exactly one:

   - **Exploitable** — attacker-controlled input reaches a dangerous operation; data flow traced end-to-end. Fix now.
   - **Defect** — a real bug in the code (UAF, OOB, strcpy, off-by-one, null deref, unchecked allocation, format-string, etc.). Exploitability depends on callers. We may have traced some reachability in this scan, but reviewers cannot enumerate every consumer of a function — especially in monorepos, libraries, or code that may be reused in future. Report the bug; note what we did and didn't verify about reachability. The downstream reader decides what reachability means for them.
   - **Quality / correctness** — brittle code, fragile pattern, defense-in-depth gap. Not a concrete bug today but a future bug if the code evolves.
   - **False positive** — rule misfired. Explain why (constant input, unreachable code, already validated, different bug class than rule claims).

5. **For exploitable findings**, note: what's the impact? How would an attacker reach this? What's the fix?

Note: a pure crash (null deref, divide-by-zero, allocation-failure not checked) is a **defect**, not a separate bucket. If the crash is triggered by attacker-controlled input on a long-running process, reclassify as exploitable (single-request daemon crashes are real DoS, independent of the DoS exclusion policy which applies to resource-exhaustion noise). Whether a defect is "exploitable today" depends on caller context we may not see — err on the side of reporting it as a defect with an honest caveat.

### Output

Write `$MIRRORED/triage.md` with **all four buckets**, even when they are empty — keeps the artifact structure stable for follow-on questions:

```markdown
# Semgrep Triage

## Exploitable

### [HIGH] SQL injection in `src/db.py:42`
- **Rule:** python.lang.security.audit.formatted-sql-query
- **Verdict:** Exploitable. `name` parameter comes from HTTP request (src/api.py:38) and reaches query unsanitized.
- **Evidence:** `static_corroboration`
- **Impact:** Full database read/write via crafted input.
- **Fix:** Use parameterized query.

## Defects

### `src/util.c:103` — use of `gets()`
- **Verdict:** Defect. `gets` is unsafe and unbounded. In this scan's scope, the only caller is an internal self-test passing a constant. Reachability from attacker input in other contexts (other services in this monorepo, downstream library consumers, future refactors) was not verified.
- **Evidence:** `pattern_match`
- **Fix:** replace with `fgets(buf, sizeof(buf), stdin)`.

### `src/parser.c:218` — null deref on malformed config
- **Verdict:** Defect. `strchr` return not checked before deref. Crashes the process on malformed input. In this scan's scope, config is read at startup from a root-owned path; we did not verify that every deployment uses that path. If the config path becomes attacker-writable (e.g. different deployment, shared-hosting), this becomes a crash-on-demand.
- **Evidence:** `static_corroboration`
- **Fix:** check for NULL before deref; return a parse error.

## Quality / Correctness

### `src/net.c:92` — missing errno check after recv()
- **Verdict:** `recv()` return value used without checking for -1. On transient network error, produces garbage bytes in the buffer. Not a concrete bug today (garbage stays within bounds), but defensively wrong.

## False Positives

### `src/crypto.py:17` — insecure-hash-algorithm-md5
- **Verdict:** False positive. MD5 used for non-security cache key, not authentication.
```

**Default is important-only.** Triage against the `*-important.json` files from Phase 1's post-filter (not the raw `.json`). The five-bucket structure still applies — important-only filters what **enters** triage, not what bucket a finding lands in.

If the user **did** ask for `all bugs`, triage the full raw JSON. Prioritize ERROR → WARNING → INFO severity. If there are many findings (>50), triage ERRORs and WARNINGs fully, then sample INFOs.

---

## Phase 3: Code Review

Read the codebase and look for bugs, vulnerabilities, and design issues that pattern-matching can't catch. Phase 3 runs **multiple independent review passes** in parallel to maximize recall, then merges and deduplicates findings.

This prompt synthesizes practices from Anthropic's production /security-review, Google Project Zero's Naptime/Big Sleep agent, and the Semgrep/Crash Override writeups on LLM-driven code review. It's opinionated — follow the structure even if it feels heavy.

### Multi-pass architecture

Phase 3 runs N independent review passes in parallel (default: 3, configurable via `passes:N` or `1 pass`). Each pass is a subagent that independently reviews the codebase. This exploits LLM non-determinism — each pass naturally explores different code paths and catches different bugs.

**Step 3.0: Orient (runs once, in the parent).** Before spawning review passes, the parent builds a system map that all passes will receive:

- What does the project do? (read the README or top-level file if present)
- What are the entry points for untrusted input? (HTTP handlers, CLI args, file readers, socket listeners, deserialization, IPC, env vars)
- What are the privileged sinks? (exec, SQL, file writes, auth decisions, crypto operations, memory allocation with external sizes)
- What's the trust boundary? Where does the code decide "this input is now safe"?
- List all source files and their approximate purpose (1 line each)
- If Phase 1 ran: read `$MIRRORED/semgrep/parse-failures.txt` — these files have zero semgrep coverage and must be reviewed
- If Phase 2 ran: read `$MIRRORED/triage.md` for context on what semgrep already found

Write the orient summary to `$MIRRORED/orient.md`. This is an intermediate artifact used to brief subagents — it is not a deliverable.

**Step 3.1: Spawn review passes.** Launch N subagents in parallel using the Agent tool. Each subagent receives:

1. The orient summary (full text of `orient.md`)
2. The target directory path
3. The full review methodology (Role, Bug-class checklist, Hard exclusions, Confidence threshold, Output format) — copied verbatim from this skill into the subagent prompt
4. The instruction: "You are review pass K of N. Conduct an independent security review. Write your findings to `$MIRRORED/review_pass_K.md`."

Each subagent writes its own `review_pass_K.md` using the same finding format as the Output section below.

**Do NOT tell later passes what earlier passes found.** The passes must be independent — anchoring on prior findings defeats the purpose. The whole point is that each pass explores the codebase with fresh eyes, and non-determinism naturally leads to different coverage.

**Step 3.2: Merge and deduplicate (runs in the parent after all passes complete).**

1. Read all `review_pass_K.md` files.
2. Deduplicate: two findings are the same if they reference the same location (file + line range) and the same bug class. Keep the version with the richer description / more complete data flow trace.
3. If different passes found the same bug but described it differently, merge the best parts of each description.
4. If a finding appears in multiple passes, note this — it's a signal of higher confidence.
5. Write the merged, deduplicated result to `$MIRRORED/review.md`.
6. Delete the intermediate `review_pass_K.md` files and `orient.md`.

The merge header in `review.md` should note: `**Review passes:** N (findings appearing in multiple passes noted)`.

### Role (passed to each subagent)

You are a senior security engineer auditing this codebase for exploitable vulnerabilities. Your goal is **high-confidence findings with real exploitation potential**, not an exhaustive list of every theoretical concern. Better to miss some theoretical issues than flood the report with false positives.

### Review methodology (passed to each subagent)

**Always ignore test code.** Skip any file whose path contains `test`, `tests`, `spec`, `mocks`, `fixtures`, `testdata`, `benchmark`, `examples`; or whose basename matches `test_*`, `*_test.*`, `*.test.*`, `*.spec.*`. Findings in test code are not reported. The only exception is `include tests` invocation.

**Form hypotheses, then verify.** This is a ReAct loop: *hypothesize → read related code → confirm or discard*. Don't report a hypothesis as a finding until you've actually traced the data flow.

For each suspicious pattern you notice:
1. State the hypothesis precisely (what's the bug class, what's the mechanism, what's the impact?)
2. Verify by reading related code — the callers, the callees, the struct definitions, the bounds checks. Use Grep to find every use site.
3. Either confirm (finding), refute (discard), or mark as partial (write it down, keep looking).

Do **not** just list concerns. Every reported finding must have traced data flow from attacker-controlled input to the dangerous operation.

**Report.** Only findings where you'd bet on real exploitability.

### Bug-class checklist

Actively check each of these against specific code. This is not a list to tick off verbally; it's patterns to hunt for when you're reading.

**Memory safety**
- Out-of-bounds read/write, off-by-one (`>` where `>=` is needed)
- Use-after-free, double-free (especially on error-unwind paths where ownership is unclear)
- Stack/heap overflow via unbounded copy (strcpy, sprintf, unchecked memcpy, fgets with wrong size)
- Uninitialized memory used as data or pointer

**Integer bugs**
- Overflow/underflow in arithmetic, especially multiplication for allocation size
- Signed/unsigned comparison mismatch
- Integer width/type-size mismatch on assignment — wider type stored into narrower field with silent truncation; truncated value later compared against untruncated
- Left-shift of signed value into sign bit (UB)
- Wraparound that violates a downstream invariant

**Sentinel / magic-value misuse**
- A sentinel (-1, 0xFFFF, NULL, 0xDEADBEEF) used to mean "invalid" or "uninitialized"
- Sentinel collision — legitimate value equals the sentinel after truncation or computation
- Sentinel stored in a type too narrow to distinguish from real values

**Logic / state**
- Missing invariant checks between related counters (len vs capacity, index vs size)
- Assumptions that hold for spec-conformant input but not attacker-crafted
- Ownership confusion in cleanup paths (who frees what, especially in recursive or error flows)
- TOCTOU, race conditions in shared state
- Error paths that fail open (grant access on parse error, skip verification on timeout)

**Input validation / trust boundaries**
- Attacker-controlled lengths/counts used without upper bounds
- Values from input used as array indices without validation
- Bounds checks on a different value than the one ultimately used
- Data flowing across a trust boundary without re-validation

**Injection / dangerous sinks**
- Untrusted input reaching exec/shell/SQL/path/regex/format-string/template sinks
- Deserialization of untrusted data (pickle, YAML.load, unmarshal)

**Crypto / secrets**
- Weak algorithms (MD5/SHA1 for security, DES, RC4)
- Hardcoded keys, IVs, or nonces
- Predictable randomness (rand, time-seeded PRNG for security contexts)
- Timing side-channels in comparison (memcmp for tokens)

**Information leaks**
- Verbose errors exposing internal state
- Debug endpoints in production paths
- Secrets in logs or HTTP responses

### Hard exclusions — do not report

These are noise at this layer. Skip them even if you notice them:

- Denial-of-service from large or malformed input, unless it's triggerable by a single crafted request that crashes the process
- Rate limiting / resource exhaustion concerns
- Theoretical race conditions without a concrete interleaving and exploit
- Regex ReDoS unless it's reachable with attacker-controlled patterns
- Missing CSRF tokens on endpoints that don't modify state
- Client-side permission checks (they exist for UX, real checks belong server-side)
- "Should use a constant-time compare" without evidence of an actual timing oracle
- Code style, naming, maintainability, performance
- Hypothetical concerns ("if someone added a caller that did X...") — trace real call sites only
- Missing input validation in private helper functions whose only caller validates upstream
- `memset` on buffers that don't contain secrets
- `strcpy`/`sprintf` where the source is a compile-time constant

### Confidence threshold

**Default:** only report a finding if you're **≥80% confident** it's exploitable in practice, given the actual call sites and input sources you traced. Findings that don't meet this bar either get discarded or go in a "Notes" section clearly marked as lower-confidence — never in the main findings.

**If the user invoked the skill with `all bugs` / `no filter` / `include low`:** drop the confidence gate. Report everything you'd bet is a real issue at any confidence level, including speculative concerns and defense-in-depth items, with honest confidence labels on each. Do not use this mode as an excuse to invent findings — unchecked speculation is still out.

### Finding format (passed to each subagent)

Every finding must use this exact structure:

```markdown
### N. [SEVERITY] One-line title naming the bug and location
- **Location:** `path/to/file.ext:line` or `:line-range`
- **Class:** <one tag from the checklist, e.g. "heap-overflow via unchecked length", "double-free on error path">
- **Evidence:** `static_corroboration`
- **Trigger:** concrete input/condition an attacker supplies (e.g. "POST /upload with Content-Length > 8192")
- **Data flow:** 1-3 line trace from attacker input to dangerous operation, naming the specific functions and lines
- **Impact:** what the attacker achieves (RCE, auth bypass, data disclosure, etc.)
- **Confidence:** HIGH | MEDIUM — justify in one sentence
- **Recommendation:** concrete fix
```

Severity:
- **CRITICAL** — RCE, auth bypass, trivial data theft at scale
- **HIGH** — memory corruption, injection in authenticated path, significant data disclosure
- **MEDIUM** — logic bug with meaningful impact, weak crypto in a relevant path
- **LOW** — defense-in-depth issues that still merit a fix

### Example of the reasoning structure (format only — not a real bug)

> **[HIGH] Unchecked length in `parse_header()` → stack overflow in `src/proto.c:142`**
> - **Location:** `src/proto.c:142`
> - **Class:** stack-buffer-overflow via unbounded copy
> - **Evidence:** `static_corroboration`
> - **Trigger:** peer sends a `HELLO` frame where the `name` field exceeds 128 bytes
> - **Data flow:** `read_frame()` (src/proto.c:88) reads up to 8192 bytes into `frame.body`; `parse_header()` (:142) `memcpy`s `frame.name` into a 128-byte stack buffer `name_buf` using `frame.name_len`, which is only validated to be non-zero (:140) — never against `sizeof(name_buf)`.
> - **Impact:** Remote code execution via stack corruption. No authentication required.
> - **Confidence:** HIGH. Verified both call sites of `parse_header` and confirmed both pass attacker-controlled `frame.name_len` without any upstream bounds check.
> - **Recommendation:** reject frames where `name_len > sizeof(name_buf)` before the `memcpy`, or use `memcpy(name_buf, frame.name, MIN(frame.name_len, sizeof(name_buf)-1))` plus a parse error.

This is a fake example, shown for structure only. Do not pattern-match your findings against it.

### Don't (passed to each subagent)

- Don't enumerate every file systematically — follow the code, not the directory tree
- Don't invent findings to pad the report; a focused report with 2-3 real bugs beats a noisy report with 15 maybes
- Don't report items from the "hard exclusions" list
- Don't write findings that boil down to "this function lacks input validation" — name the attacker input, the sink, and the gap
- Don't stop after one finding if there are more; but also don't manufacture more if there aren't

### Per-pass output format

Each subagent writes its `review_pass_K.md` using the three-section structure (Exploitable, Defects, Quality/Correctness), all present even if empty.

### Final output

After merge and deduplication (Step 3.2), the parent writes `$MIRRORED/review.md`:

```markdown
# Code Review Findings

**Target:** /absolute/path/to/codebase
**Date:** YYYY-MM-DD
**Mode:** important-only | all-bugs
**Review passes:** 3 (findings appearing in multiple passes noted)
**Semgrep parse failures reviewed:** N files

## Exploitable

### 1. [CRITICAL] Unauthenticated admin endpoint
- **Location:** `src/api/admin.go:55-72`
- **Class:** missing authorization
- **Evidence:** `static_corroboration`
- **Trigger:** any HTTP client POSTs to `/admin/reset`
- **Data flow:** no auth middleware registered on this route (main.go:44); handler unconditionally wipes the users table
- **Impact:** full data loss
- **Confidence:** HIGH — found in 3/3 passes
- **Recommendation:** add auth middleware consistent with other admin routes

## Defects

### 1. `src/util.c:103` — unbounded `gets()`
- **Bug:** `gets` with no length check reads into a 128-byte buffer.
- **Evidence:** `pattern_match`
- **Reachability in this scan:** only caller found is `tests/self_test.c` passing a constant.
- **Reachability we did NOT verify:** shared utility module; may be consumed by other code.
- **Fix:** replace with `fgets(buf, sizeof(buf), stdin)`.

## Quality / Correctness

### 1. `src/net.c:92` — missing errno check after recv()
- `recv()` return value used without checking for -1. Defensively wrong but stays within bounds.
```

Phase 3 does NOT produce the final consolidated report — that's Phase 5's job. `review.md` stays frozen once written.

---

## Phase 4: Proof-of-Bug

Attempt to build the project with sanitizers, generate PoC inputs, and validate findings via a patch oracle. **Only runs when the user explicitly requests it** (`prove`, `with proof`, `confirm bugs`, `full pipeline`).

### Scope and budget

Collect all findings from Phases 2-3 that are classified as **Exploitable** or **Defect** with evidence ≥ `static_corroboration`. These are candidates for proof.

- If ≤10 candidates: attempt proof for all, starting with highest severity.
- If >10 candidates: sort by (severity descending, confidence descending). Attempt the top 10. Report the rest as "not attempted — budget exceeded."

### Parallelization

Step 4a (build) is serial — all findings share one sanitizer-instrumented build. Steps 4b-4c (PoC + patch oracle) are independent per-finding and can run as parallel subagents after the build completes. Each subagent gets the build artifact path, one finding's details, and writes its results to `proof/finding_N_result.md`. The parent merges into `proof/proof.md` and deletes intermediates.

For ≤3 findings, run inline (no subagents). For >3 findings, parallelize.

### Step 4a: Build Discovery and Sanitizer Strategy

The goal is to build the project's **real binary/library** with sanitizers — not to copy files out and compile them standalone. Large projects with internal dependencies, generated headers, or complex link graphs cannot be compiled piecemeal. Always use the project's own build system.

**4a-i. Detect the build system.** Check for these files in the target directory, in order:

| File(s) | Build system |
|---|---|
| `BUILD`, `BUILD.bazel`, `WORKSPACE`, `WORKSPACE.bazel`, `MODULE.bazel` | Bazel |
| `CMakeLists.txt` | CMake |
| `Makefile`, `GNUmakefile` | Make |
| `configure`, `configure.ac` | Autotools |
| `meson.build` | Meson |
| `Cargo.toml` | Cargo |
| `go.mod` | Go |
| `package.json` | npm/yarn |
| `pyproject.toml`, `setup.py` | Python |
| `*.sln`, `*.csproj` | .NET |

**4a-ii. Check for existing sanitizer/debug build modes.** Before injecting flags yourself, interrogate the build system — many projects already have a way to build with sanitizers:

- **CMake:** Look for presets or options:
  - `grep -r "SANITIZE\|ASAN\|sanitize" CMakeLists.txt cmake/` — projects often have `-DENABLE_ASAN=ON` or `-DCMAKE_BUILD_TYPE=ASan`
  - Check `CMakePresets.json` or `cmake/` dir for sanitizer presets
  - Check if there's a `Debug` build type that enables sanitizers
- **Bazel:** Check for sanitizer configs:
  - `grep -r "sanitize\|asan" .bazelrc BUILD`
  - Look for `--config=asan` in `.bazelrc` (common convention)
  - Bazel native: `bazel build --features=asan //target` or `--copt=-fsanitize=address --linkopt=-fsanitize=address`
- **Make:** Check Makefile for debug/sanitizer targets:
  - `grep -i "asan\|sanitize\|debug" Makefile` — look for `make asan`, `make debug`, `make sanitize`
  - Check if `CFLAGS` / `LDFLAGS` are respected (overrideable from command line)
- **Meson:** Check for sanitizer options:
  - `meson configure` lists options; `b_sanitize` is the built-in sanitizer option
  - `meson setup build -Db_sanitize=address,undefined`
- **Cargo:** `RUSTFLAGS="-Zsanitizer=address"` (requires nightly)
- **Go:** `-race` flag; no ASan equivalent. Use the project's test suite.
- **Autotools:** Check `./configure --help | grep -i sanitize`

If the project has a documented sanitizer mode, **use it**. It handles link dependencies, custom allocators, and suppression files correctly. Only fall back to flag injection if no built-in mode exists.

**4a-iii. Build with sanitizers.** Based on what you found:

| Scenario | Approach |
|---|---|
| Project has `-DENABLE_ASAN=ON` or `--config=asan` or `make asan` | Use the project's own mode |
| Make with overrideable CFLAGS | `make CFLAGS="-fsanitize=address,undefined -fno-omit-frame-pointer -g -O1" LDFLAGS="-fsanitize=address,undefined"` |
| CMake, no preset | `cmake -B build-asan -DCMAKE_C_FLAGS="-fsanitize=address,undefined -fno-omit-frame-pointer -g" -DCMAKE_EXE_LINKER_FLAGS="-fsanitize=address,undefined" && cmake --build build-asan` |
| Bazel, no config | `bazel build --copt=-fsanitize=address --copt=-fsanitize=undefined --linkopt=-fsanitize=address --linkopt=-fsanitize=undefined //target` |
| Meson | `meson setup build-asan -Db_sanitize=address,undefined && meson compile -C build-asan` |
| Single-file / trivial Makefile | Direct compiler invocation is acceptable (see below) |

For **single-file projects or trivial builds** (no internal deps beyond what's in one compilation unit), direct compiler invocation is fine:
```bash
gcc -fsanitize=address -fsanitize=undefined -fno-omit-frame-pointer -g -O1 \
    -o "$MIRRORED/proof/server_asan" "$TARGET/src/server.c" -lpthread
```

For **projects with internal dependencies**, always build through the build system. Never try to manually resolve include paths and link dependencies for a large project.

**4a-iv. Identify the target binary/library.** After building, determine what executable or library to test against:
- For servers/CLIs: the built binary
- For libraries: you'll need a test harness (Step 4b)
- Record the path to the built artifact

**If compilation fails:** record the error in `proof/build.log`, report "build failed — evidence stays at `static_corroboration`", and skip to Phase 5. Don't spend more than 3 attempts fixing build issues.

```bash
mkdir -p "$MIRRORED/proof"

{
  echo "Build system: <detected>"
  echo "Existing sanitizer mode: <what was found, or 'none'>"
  echo "Build command: <exact command used>"
  echo "Sanitizers: ASan + UBSan (or what's available)"
  echo ""
  echo "--- Build output ---"
} > "$MIRRORED/proof/build.log"

<build_command> >> "$MIRRORED/proof/build.log" 2>&1
BUILD_OK=$?

if [ $BUILD_OK -ne 0 ]; then
  echo "BUILD FAILED — see proof/build.log" >> "$MIRRORED/proof/build.log"
fi
```

### Step 4b: PoC Generation

For each candidate finding (in priority order):

1. **Read the finding** — location, bug class, trigger description, data flow.
2. **Write a minimal PoC** that exercises the bug. The PoC type depends on what the project is:

   | Project type | PoC approach |
   |---|---|
   | Server (HTTP, WebSocket, etc.) | Script (Python) that sends crafted requests to the running server |
   | CLI tool | Script that invokes the binary with crafted arguments/stdin |
   | Library with public API | Small C/Go/Python harness that links against the built library and calls the vulnerable function |
   | Library with only internal APIs | Harness that `#include`s the source directly (acceptable for small files) or uses `dlsym`/`-Wl,--whole-archive` to access internal symbols |

3. **Run the PoC** against the sanitizer-instrumented build.
   - For servers: start the ASan-built server, run the PoC script, then stop the server and check its stderr for sanitizer output.
   - For harnesses: compile the harness linking against the ASan-built library, then run it.
   - For CLIs: run the ASan-built binary with crafted input.

4. **Check the result:**
   - ASan/UBSan report → `crash_reproduced`. Save sanitizer output to `proof/finding_N_asan.txt`.
   - Crash (segfault, abort) → `crash_reproduced`. Save crash info.
   - Observable misbehavior matching the predicted bug (e.g., path traversal reads a file it shouldn't) → `crash_reproduced`.
   - Clean exit, no error → finding stays at `static_corroboration`. Note "PoC did not trigger."

**Example — server-based PoC:**
```python
#!/usr/bin/env python3
"""PoC for Finding 1: path traversal in file serving."""
import socket, subprocess, time, tempfile, os

SERVER_BIN = "/path/to/asan-built/server"
# Start server, send crafted request, check response/stderr for evidence
```

**Example — library harness PoC:**
```bash
# Compile harness against the ASan-built library
gcc -fsanitize=address,undefined -g -O1 \
    -I"$TARGET/include" -o "$MIRRORED/proof/poc_1" \
    "$MIRRORED/proof/poc_1.c" \
    -L"$TARGET/build-asan/lib" -lmylib -Wl,-rpath,"$TARGET/build-asan/lib"
```

### Step 4c: Patch Oracle

For each finding that reached `crash_reproduced`:

1. **Write a minimal fix** — the smallest change that eliminates the bug. Save as `proof/patch_N.diff`.
2. **Apply the patch** to the source tree (or a worktree — see below) and **rebuild using the same build system and sanitizer flags**.
3. **Re-run the same PoC** against the patched build.
4. **Evaluate:**
   - PoC no longer triggers → `patch_validated`. The fix causally addresses the bug.
   - PoC still triggers → the theory was wrong, or the fix was incomplete. Stay at `crash_reproduced` with a note. Don't iterate more than once.
   - Build fails after patch → patch was wrong. Stay at `crash_reproduced`.

**Patch application strategy** — choose based on project complexity:

| Project size | Strategy |
|---|---|
| Small (≤5 source files, no build system deps) | Copy affected file(s) to `proof/`, patch there, compile standalone |
| Medium (real build system but fast rebuild) | Apply patch in-place with `git apply`, rebuild, then `git checkout -- <file>` to restore |
| Large / slow rebuild | Use a git worktree: `git worktree add ../proof-worktree HEAD`, apply patch there, build there |

For **in-place patching** (medium projects):
```bash
# Apply patch
cd "$TARGET"
git apply "$MIRRORED/proof/patch_1.diff"

# Rebuild (same command as 4a-iii)
<same_build_command> 2>&1 | tee "$MIRRORED/proof/patch_1_build.log"

# Run PoC against patched binary
<run_poc> > "$MIRRORED/proof/poc_1_patched_output.txt" 2>&1

# Restore original source
git checkout -- .
```

For **worktree patching** (large projects):
```bash
cd "$TARGET"
git worktree add "$MIRRORED/proof/worktree" HEAD
cd "$MIRRORED/proof/worktree"
git apply "$MIRRORED/proof/patch_1.diff"
<build_command>
<run_poc>
cd "$TARGET"
git worktree remove "$MIRRORED/proof/worktree"
```

For **small standalone projects** (the copy approach still works here):
```bash
cp "$TARGET/src/server.c" "$MIRRORED/proof/server_patched.c"
# Apply fix directly to the copy
gcc -fsanitize=address,undefined -g -O1 \
    -o "$MIRRORED/proof/server_patched" "$MIRRORED/proof/server_patched.c" -lpthread
```

**File extensions matter.** When copying source files for patching, keep a `.c` / `.cpp` / `.cc` extension — gcc/clang infer the language from the extension.

### Step 4d: Write Proof Summary

After all proof attempts, write `$MIRRORED/proof/proof.md`. This is Phase 4's artifact — it does NOT edit `review.md` or any other phase's output. Phase 5 will read this to apply final evidence levels in the consolidated report.

```markdown
# Proof-of-Bug Results

**Build system:** CMake with gcc 13.2
**Sanitizers:** ASan + UBSan
**Findings attempted:** 3 of 5

| # | Finding | Evidence Before | Evidence After | Artifacts |
|---|---------|----------------|----------------|-----------|
| 1 | Stack overflow in log_request() | static_corroboration | patch_validated | poc_1.c, patch_1.diff |
| 2 | Integer truncation in parse_len() | static_corroboration | crash_reproduced | poc_2.c |
| 3 | NULL deref in config parser | static_corroboration | static_corroboration | poc_3.c (did not trigger) |
| 4 | Use of gets() in util.c | pattern_match | not attempted | — |
| 5 | Missing bounds check in net.c | suspicion | not attempted | — |

## Finding 1: Stack overflow in log_request()

**PoC:** `poc_1.c` — calls log_request() with 256-byte payload.
**Result:** ASan reports stack-buffer-overflow at log.c:44 (see `poc_1_output.txt`).
**Patch:** `patch_1.diff` — replaces strcpy with snprintf.
**Patch oracle:** PoC runs cleanly after patch (see `poc_1_patched_output.txt`). Evidence promoted to `patch_validated`.

## Finding 2: ...
```

---

## Phase 5: Final Report

Synthesize all findings from Phases 2-4 into a single authoritative report, apply final evidence levels, and document variant patterns for confirmed bugs. **Only runs when the user explicitly requests it** (`variants`, `variant analysis`, `full pipeline`).

Phase 5 reads `triage.md`, `review.md`, and `proof/proof.md` (if they exist) and produces one consolidated `report.md`. This is the deliverable — the reader shouldn't need to look at earlier artifacts unless they want working details.

### Steps

1. **Read all prior phase artifacts** — `triage.md`, `review.md`, `proof/proof.md`.
2. **Merge and deduplicate findings.** A finding that appears in both triage and review is listed once, with the richer description.
3. **Apply final evidence levels.** If Phase 4 promoted a finding (e.g., `static_corroboration` → `patch_validated`), use the promoted level in the report.
4. **For each finding at `crash_reproduced` or `patch_validated`, write variant documentation** (see below).
5. **Write `$MIRRORED/report.md`** using the template below.

### Variant Documentation

For every confirmed finding, document the bug pattern:

1. **Extract the abstract pattern.** What structural property made this bug possible? Not variable names — the shape.
2. **Search the codebase for structural matches.** Grep for same API calls, same data flow patterns, same cast patterns.
3. **Write a semgrep rule sketch** if feasible — include structural constraints so it's not too broad.
4. **List other instances** found and assess whether they're also exploitable.

### Output

Write `$MIRRORED/report.md`:

```markdown
# Security Audit Report

**Target:** /absolute/path/to/codebase
**Date:** YYYY-MM-DD
**Phases run:** 1, 2, 3, 4, 5
**Mode:** important-only | all-bugs
**Semgrep parse failures:** N files

## Summary

<2-3 sentence overview: what was scanned, what was found, overall assessment>

## Exploitable

### 1. [CRITICAL] Title
- **Location:** `path:line`
- **Class:** bug class
- **Evidence:** `patch_validated`
- **Trigger:** concrete attacker input
- **Data flow:** source → sink trace
- **Impact:** what attacker achieves
- **Confidence:** HIGH
- **Recommendation:** concrete fix

## Defects

### 1. `path:line` — title
- **Bug:** description
- **Evidence:** `static_corroboration`
- **Reachability in this scan:** what was verified
- **Reachability we did NOT verify:** what wasn't
- **Fix:** concrete fix

## Quality / Correctness

### 1. `path:line` — title
- Description of fragile pattern or defense-in-depth gap.

## Proof-of-Bug Summary

| # | Finding | Evidence Before | Evidence After | Artifacts |
|---|---------|----------------|----------------|-----------|
| 1 | ... | static_corroboration | patch_validated | poc_1.c, patch_1.diff |

## Variant Patterns

### Variant 1: <pattern name>

**Source finding:** Finding N — <title>
**Abstract pattern:** <1-2 sentence structural description>

**Detection heuristic:**
- Grep: `<regex>`
- Semgrep rule sketch:
  ```yaml
  rules:
    - id: <pattern-name>
      pattern: ...
      severity: WARNING
      languages: [c, cpp]
  ```

**Other instances in this codebase:**
- `path:line` — description — exploitable / safe (reason)

**Assessment:** N instances found, M potentially exploitable.

## Coverage Notes

- **Files semgrep couldn't parse:** N (see `semgrep/parse-failures.txt`)
- **Test code:** excluded
- **Vendored / third-party code:** excluded
- **What was NOT reviewed:** <out-of-scope items>

## Semgrep Triage Summary

- **Total raw findings:** N
- **After important-only filter:** N
- **Triaged as exploitable:** N
- **Triaged as defects:** N
- **Triaged as quality / correctness:** N
- **Triaged as false positives:** N
```

### If Phase 4 did not run

If only Phases 1-3 + 5 ran (user said `variants` but not `prove`), the report omits "Proof-of-Bug Summary" and "Variant Patterns" sections. Evidence levels stay as-is from Phase 3. The report is still the authoritative consolidated output.

### If Phase 5 runs standalone

Phase 5 can run after a previous session produced phases 1-4. It reads whatever artifacts exist under `$MIRRORED/` and synthesizes. Missing phases are noted in Coverage Notes.

---

## Cleanup (always run at the end)

Before reporting completion, scrub transient artifacts from `$OUTPUT_DIR` and anywhere else the skill touched. Do this unconditionally — don't leave empty files or scratch dirs behind.

```bash
# Delete empty .stderr files (keep non-empty ones — they're useful for debugging)
find "$OUTPUT_DIR" -name '*.stderr' -empty -delete
```

(Semgrep is invoked with `--quiet` above, so `.stderr` files are empty on success. If a ruleset failed, its stderr will have content and will be kept for debugging.)

If the skill created any other temporary files during a run (intermediate jq pipes, temp copies, scratch notes under `/tmp`, etc.), delete them in this step.

**Keep:**
- `report.md` — final consolidated report (Phase 5)
- `review.md` — manual code review findings (Phase 3)
- `triage.md` — semgrep triage (Phase 2)
- `semgrep/*.json` — raw findings, source of truth for re-triage
- `semgrep/*-important.json` — filter output (if important-only mode was used)
- `proof/` — proof.md + PoC source, sanitizer output, patches, build log (Phase 4)
- Any `.stderr` file that has content (something actually failed — the user needs to see it)

**Delete:**
- Empty `.stderr` files
- `orient.md` — Phase 3 intermediate (should already be deleted in Step 3.2)
- `review_pass_*.md` — Phase 3 per-pass intermediates (should already be deleted in Step 3.2)
- `triage_chunk_*.md` — Phase 2 per-chunk intermediates (should already be deleted after merge)
- Any scratch files the skill itself created during the run
- Any temp dirs under `/tmp` that the skill invented for its own bookkeeping

Never delete files the user already had or anything outside `$OUTPUT_DIR` / the skill's own scratch paths.

---

## Anti-patterns

- `--config auto` or `--config p/...` — network downloads
- Quoting `--severity WARNING --severity ERROR` as one shell argument
- `--include` on cross-language rule directories
- Skipping `--metrics=off`
- Classifying a semgrep finding as "false positive" without reading the actual source code in context
- Reviewing only files semgrep flagged — Phase 3 should find things semgrep missed
- Listing every file read instead of focusing on what's wrong
- Copying source files out of tree and compiling standalone for projects with real build systems — use the project's build system
- Modifying original source files without restoring them — use `git apply` + `git checkout`, worktrees, or copies for small projects
- Spending more than 3 attempts fixing build failures — report and move on
- Running Phase 4 on `suspicion`-level findings — waste of cycles; only `static_corroboration` and above
- Writing variant semgrep rules that are too broad (will fire on every `strcpy` call) — include structural constraints
