---
name: semgrep-skill
description: >-
  Run an offline Semgrep static analysis scan on a codebase using a bundled,
  network-free rule set (semgrep-rules + 0xdea-rules). Auto-detects languages
  and picks matching rule directories. Use when asked to scan code for
  vulnerabilities, run a security audit with Semgrep, find bugs, or perform
  static analysis without network access. Targets C, C++, Python, Go,
  JavaScript, TypeScript, Rust, and C#.
allowed-tools:
  - Bash
  - Read
  - Glob
---

# Semgrep Security Scan (Offline)

Run a Semgrep scan against a target directory using only locally bundled rules. No network, no Pro, no telemetry.

## Invocation Options

The user may include any of these phrases in the request. Detect them from the prompt — there is no formal flag parser.

| Phrase (any synonym) | Effect |
|---|---|
| `important only`, `important-only`, `high severity only` | Enable **important-only mode** (severity + metadata filter) |
| `as json`, `output as json`, `json output`, `json` | Print a compact JSON summary to chat instead of the human bullet report; the per-ruleset JSON files are written either way |
| `output to <dir>`, `into <dir>` | Use `<dir>` as `OUTPUT_DIR` instead of auto-incremented default |

Defaults: run-all coverage, human-readable chat report, output dir = `./static_analysis_semgrep_N` (auto-incremented).

## When to Use

- Security audit of a codebase in an offline environment
- First-pass static analysis, finding known bug patterns

## When NOT to Use

- Need cross-file taint analysis → this skill is OSS-only; consider CodeQL
- Already have Semgrep CI configured → use the existing pipeline

## Hard Rules

1. **Always pass `--metrics=off`** — semgrep sends telemetry by default.
2. **Only use locally bundled rule directories** under `{baseDir}/rules/`. Never `--config p/...`, never `--config auto`, never a URL, never `git clone`. If a needed directory is missing on disk, fail loudly — do not fetch.
3. **Never pass `--pro`** — this skill is OSS-only by design for reproducibility.

## How It Works

### 1. Resolve `OUTPUT_DIR` and verify semgrep

```bash
if [ -n "$USER_SPECIFIED_DIR" ]; then
  OUTPUT_DIR="$USER_SPECIFIED_DIR"
else
  N=1; while [ -e "static_analysis_semgrep_$N" ]; do N=$((N+1)); done
  OUTPUT_DIR="static_analysis_semgrep_$N"
fi
mkdir -p "$OUTPUT_DIR"
command -v semgrep >/dev/null || { echo "ERROR: semgrep not installed"; exit 1; }
```

### 2. Detect languages

Use **Glob** (not Bash) against the target directory:

| Pattern | Language |
|---|---|
| `**/*.py` | Python |
| `**/*.go` | Go |
| `**/*.c`, `**/*.cc`, `**/*.cpp`, `**/*.cxx`, `**/*.h`, `**/*.hpp` | C / C++ |
| `**/*.js`, `**/*.jsx`, `**/*.mjs`, `**/*.cjs` | JavaScript |
| `**/*.ts`, `**/*.tsx` | TypeScript |
| `**/*.rs` | Rust |
| `**/*.cs`, `**/*.cshtml`, `**/*.razor` | C# |

If `package.json`, `pyproject.toml`/`requirements.txt`, `go.mod`, or `Cargo.toml` exist, Read them to spot major frameworks (Django, Flask, FastAPI, React, Express, gRPC, GORM, etc.).

### 3. Pick rule directories

Look up each detected language in [references/rulesets.md](references/rulesets.md) and assemble an absolute-path list:

- Always include the cross-language directories (`semgrep-rules/generic`, `semgrep-rules/problem-based-packs`).
- Add the primary directory for each detected language.
- Add framework directories for each detected framework.
- If C or C++: add `0xdea-rules/rules/c` (memory-safety rules not in the official set).

Resolve `{baseDir}` once to the absolute path of this skill (e.g., `/Users/<you>/.claude/skills/semgrep-skill`) and use it throughout.

### 4. Run semgrep in parallel

Run all rule directories in parallel from a single `Bash` call. Always pass the target as an absolute path. Always pass each `--severity` flag as a **separate shell token** — never as one quoted string.

```bash
TARGET=/abs/path/to/codebase
BASE=/abs/path/to/semgrep-skill   # {baseDir}
SEV=()  # important-only mode: SEV=(--severity WARNING --severity ERROR)

run() {
  local dir="$1" name="$2"; shift 2
  semgrep --metrics=off "${SEV[@]}" "$@" \
    --config "$dir" --json -o "$OUTPUT_DIR/$name.json" \
    "$TARGET" 2>"$OUTPUT_DIR/$name.stderr"
}

run "$BASE/rules/semgrep-rules/python/lang"   python-lang   --include='*.py' &
run "$BASE/rules/semgrep-rules/python/django" python-django --include='*.py' &
run "$BASE/rules/semgrep-rules/c/lang"        c-lang        --include='*.c' --include='*.cpp' --include='*.h' --include='*.hpp' &
run "$BASE/rules/0xdea-rules/rules/c"         c-0xdea       &
run "$BASE/rules/semgrep-rules/generic"       generic       &
wait
```

Notes:
- **Use `--include` only for language-specific directories.** Cross-language directories (`generic`, `problem-based-packs`, `0xdea-rules/rules/c`) get **no** `--include`.
- `--severity` only accepts `INFO`, `WARNING`, `ERROR` (semgrep OSS). Do not pass `LOW`/`MEDIUM`/`HIGH`/`CRITICAL` — those are JSON metadata values and will fail with `option '--severity': invalid value`.
- Capture stderr per-run so individual ruleset failures are debuggable without poisoning the JSON.

### 5. (Important-only mode) Post-filter the JSON

Important-only mode applies two layers: `--severity WARNING --severity ERROR` at scan time (above), plus a metadata jq filter afterwards. Findings without metadata (e.g. 0xdea rules) are kept by default — we don't filter what isn't annotated.

```bash
for f in "$OUTPUT_DIR"/*.json; do
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
    errors: .errors,
    paths: .paths
  }' "$f" > "${f%.json}-important.json"
done
```

The `MEDIUM`/`HIGH` here are JSON metadata fields — that's correct; they are not CLI flag values.

### 6. Report

**Default (human report):** count findings per rule directory and produce a bullet summary grouped by severity and category. Report finding counts, the path to `$OUTPUT_DIR`, and any non-empty `.stderr` files (those indicate a ruleset that failed).

**With `json` flag:** instead of the bullet summary, emit a single JSON object to chat:

```json
{
  "output_dir": "/abs/path/static_analysis_semgrep_1",
  "mode": "run-all",
  "total_findings": 47,
  "by_severity": {"ERROR": 3, "WARNING": 12, "INFO": 32},
  "by_rule_dir": {"python-lang": 18, "c-0xdea": 7, "generic": 22},
  "files": ["/abs/.../python-lang.json", "/abs/.../c-0xdea.json"]
}
```

The per-ruleset `.json` files are produced regardless and are the source of truth — `json` mode just changes the chat summary format.

## Anti-patterns

- `--config auto` or `--config p/...` — both trigger network downloads
- Passing rule directories as URLs or `git clone`-ing them at runtime
- Quoting `--severity WARNING --severity ERROR` as a single shell argument (semgrep parses it as one bogus option)
- Using `--include` with cross-language rule directories — it filters out everything they were meant to match
- Skipping `--metrics=off`
