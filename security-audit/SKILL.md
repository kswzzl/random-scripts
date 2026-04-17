---
name: security-audit
description: >-
  Security audit of a codebase. Three phases: (1) Semgrep scan using bundled
  offline rules, (2) triage semgrep findings by reading the actual source to
  classify true/false positives, (3) general code review for bugs semgrep
  can't catch — logic flaws, auth issues, race conditions, etc. Phases can
  be run individually or together. Use when asked to audit code, find
  vulnerabilities, review security, do static analysis, or scan for bugs.
allowed-tools:
  - Bash
  - Read
  - Glob
  - Grep
---

# Security Audit

Three-phase security review: automated scan, triage, manual code review. Each phase builds on the previous one's output but can be run standalone.

## Invocation Options

Detect these from the user's prompt — no formal parser.

| Phrase | Effect |
|---|---|
| `scan only`, `semgrep only`, `phase 1` | Run Phase 1 only |
| `triage only`, `phase 2` | Run Phase 2 only (requires prior Phase 1 output) |
| `review only`, `code review only`, `phase 3` | Run Phase 3 only (skip semgrep) |
| `triage`, `scan and triage`, `phases 1-2` | Run Phases 1 + 2 |
| `all bugs`, `all findings`, `no filter`, `include low`, `noisy` | Disable the default importance filter — report everything, including low-confidence and non-security findings |
| `output to <dir>`, `into <dir>` | Custom output directory |

**Default (no flags):** all three phases, **important-only mode** (severity + metadata filter on Phase 1, ≥80% confidence on Phase 3, high-value true positives only on Phase 2). Output dir = `./security_audit_N` (auto-incremented).

**Important-only is the default across all phases** because noise defeats the point of the skill. Users who want the full unfiltered output must explicitly opt in with `all bugs` or equivalent.

## Output

All output goes to `$OUTPUT_DIR`:

```
$OUTPUT_DIR/
├── semgrep/              # Phase 1: raw semgrep JSON per ruleset
├── triage.md             # Phase 2: finding-by-finding triage
└── audit.md              # Final consolidated report (Phase 3)
```

A short chat summary is printed at the end. The full report is in `audit.md`.

---

## Phase 1: Semgrep Scan

Automated pattern-match scan using locally bundled rules. No network, no Pro, no telemetry.

### Hard Rules

1. **Always pass `--metrics=off`.**
2. **Only use rule directories under `{baseDir}/rules/`.** Never `--config p/...`, never `--config auto`, never a URL, never `git clone`.
3. **Never pass `--pro`.**

### Steps

**1a. Resolve output dir and verify semgrep:**

```bash
if [ -n "$USER_SPECIFIED_DIR" ]; then
  OUTPUT_DIR="$USER_SPECIFIED_DIR"
else
  N=1; while [ -e "security_audit_$N" ]; do N=$((N+1)); done
  OUTPUT_DIR="security_audit_$N"
fi
mkdir -p "$OUTPUT_DIR/semgrep"
command -v semgrep >/dev/null || { echo "ERROR: semgrep not installed"; exit 1; }
```

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

run() {
  local dir="$1" name="$2"; shift 2
  semgrep --metrics=off --quiet "${SEV[@]}" "$@" \
    --config "$dir" --json -o "$OUTPUT_DIR/semgrep/$name.json" \
    "$TARGET" 2>"$OUTPUT_DIR/semgrep/$name.stderr"
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
- With `--quiet`, real errors land in the JSON's `errors[]` array (not stderr). Check `jq '.errors' "$OUTPUT_DIR/semgrep/$name.json"` per-ruleset; a non-empty array means the scan failed.

**1e. Post-filter (default; skip only if user asked for all bugs):**

```bash
for f in "$OUTPUT_DIR/semgrep"/*.json; do
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

---

## Phase 2: Triage Semgrep Findings

Read each semgrep finding, look at the actual source code in context, and classify it.

### For each finding:

1. **Read the finding** from the JSON: rule ID, message, file path, line range.
2. **Read the source** at that location (use Read with enough surrounding context — typically ±20 lines).
3. **Classify:**
   - **True positive** — real bug, exploitable or clearly wrong. Note severity and exploitability.
   - **Likely true positive** — looks real but needs deeper context to confirm (e.g., depends on caller).
   - **False positive** — explain why (constant input, dead code, already validated, etc.).
4. **For true positives**, note: what's the impact? How would an attacker reach this? What's the fix?

### Output

Write `$OUTPUT_DIR/triage.md`:

```markdown
# Semgrep Triage

## True Positives

### [HIGH] SQL injection in `src/db.py:42`
- **Rule:** python.lang.security.audit.formatted-sql-query
- **Finding:** User input concatenated into SQL query
- **Verdict:** True positive. `name` parameter comes from HTTP request (line 38) and reaches query unsanitized.
- **Impact:** Full database read/write via crafted input.
- **Fix:** Use parameterized query.

### [MEDIUM] ...

## Likely True Positives
...

## False Positives

### `src/crypto.py:17` — insecure-hash-algorithm-md5
- **Verdict:** False positive. MD5 used for non-security cache key, not authentication.
```

**Default is important-only.** Phase 2 should triage against the `*-important.json` files from Phase 1's post-filter (not the raw `.json` files). Report only the true positives and likely-TPs that survive the filter; do not pad the triage with INFO-severity or low-confidence findings unless the user explicitly asked for `all bugs`.

If the user **did** ask for `all bugs`, triage the full raw JSON. Prioritize: work through ERROR severity first, then WARNING, then INFO. If there are many findings (>50), triage ERRORs and WARNINGs fully, then sample INFOs.

---

## Phase 3: Code Review

Read the codebase and look for bugs, vulnerabilities, and design issues that pattern-matching can't catch.

This prompt synthesizes practices from Anthropic's production /security-review, Google Project Zero's Naptime/Big Sleep agent, and the Semgrep/Crash Override writeups on LLM-driven code review. It's opinionated — follow the structure even if it feels heavy.

### Role

You are a senior security engineer auditing this codebase for exploitable vulnerabilities. Your goal is **high-confidence findings with real exploitation potential**, not an exhaustive list of every theoretical concern. Better to miss some theoretical issues than flood the report with false positives.

### Three-phase methodology

**A. Orient.** Before reading any code in depth, build a map of the system:
- What does it do? (read the README or top-level file if present)
- What are the entry points for untrusted input? (HTTP handlers, CLI args, file readers, socket listeners, deserialization, IPC, env vars)
- What are the privileged sinks? (exec, SQL, file writes, auth decisions, crypto operations, memory allocation with external sizes)
- What's the trust boundary? Where does the code decide "this input is now safe"?

**B. Form hypotheses, then verify.** This is a ReAct loop: *hypothesize → read related code → confirm or discard*. Don't report a hypothesis as a finding until you've actually traced the data flow.

For each suspicious pattern you notice:
1. State the hypothesis precisely (what's the bug class, what's the mechanism, what's the impact?)
2. Verify by reading related code — the callers, the callees, the struct definitions, the bounds checks. Use Grep to find every use site.
3. Either confirm (finding), refute (discard), or mark as partial (write it down, keep looking).

Do **not** just list concerns. Every reported finding must have traced data flow from attacker-controlled input to the dangerous operation.

**C. Report.** Only findings where you'd bet on real exploitability.

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

### Output

Append to `$OUTPUT_DIR/audit.md`. Every finding must use this exact structure:

```markdown
### N. [SEVERITY] One-line title naming the bug and location
- **Location:** `path/to/file.ext:line` or `:line-range`
- **Class:** <one tag from the checklist, e.g. "heap-overflow via unchecked length", "double-free on error path">
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
> - **Trigger:** peer sends a `HELLO` frame where the `name` field exceeds 128 bytes
> - **Data flow:** `read_frame()` (src/proto.c:88) reads up to 8192 bytes into `frame.body`; `parse_header()` (:142) `memcpy`s `frame.name` into a 128-byte stack buffer `name_buf` using `frame.name_len`, which is only validated to be non-zero (:140) — never against `sizeof(name_buf)`.
> - **Impact:** Remote code execution via stack corruption. No authentication required.
> - **Confidence:** HIGH. Verified both call sites of `parse_header` and confirmed both pass attacker-controlled `frame.name_len` without any upstream bounds check.
> - **Recommendation:** reject frames where `name_len > sizeof(name_buf)` before the `memcpy`, or use `memcpy(name_buf, frame.name, MIN(frame.name_len, sizeof(name_buf)-1))` plus a parse error.

This is a fake example, shown for structure only. Do not pattern-match your findings against it.

### Don't

- Don't enumerate every file systematically — follow the code, not the directory tree
- Don't invent findings to pad the report; a focused report with 2-3 real bugs beats a noisy report with 15 maybes
- Don't report items from the "hard exclusions" list
- Don't write findings that boil down to "this function lacks input validation" — name the attacker input, the sink, and the gap
- Don't stop after one finding if there are more; but also don't manufacture more if there aren't

### Output

Append findings to `$OUTPUT_DIR/audit.md`. This is the final consolidated report.

```markdown
# Security Audit Report

**Target:** /path/to/codebase
**Date:** YYYY-MM-DD
**Phases run:** 1, 2, 3

## Summary

<2-3 sentence overview: what was scanned, what was found, overall assessment>

## Critical / High Findings

### 1. [CRITICAL] Unauthenticated admin endpoint
- **Location:** `src/api/admin.go:55-72`
- **Issue:** The `/admin/reset` endpoint has no auth middleware. Any HTTP client can trigger a database reset.
- **Impact:** Full data loss.
- **Recommendation:** Add auth middleware consistent with other admin routes.

### 2. [HIGH] ...

## Medium Findings
...

## Low / Informational
...

## Semgrep Triage Summary

- **Total findings:** N
- **True positives:** N (X critical, Y high, Z medium)
- **False positives:** N
- **Details:** See `triage.md`

## Scope & Limitations

<What was reviewed, what wasn't, and any caveats>
```

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
- `audit.md`, `triage.md` — final reports
- `semgrep/*.json` — raw findings, source of truth for re-triage
- `semgrep/*-important.json` — filter output (if important-only mode was used)
- Any `.stderr` file that has content (something actually failed — the user needs to see it)

**Delete:**
- Empty `.stderr` files
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
