# Local Rule Directory Catalog

Every `--config` value passed to `semgrep` must be an absolute path under `{baseDir}/rules/`. Registry IDs (`p/python`, etc.) and URLs are forbidden — they trigger network downloads.

## Sources

| Path | Origin | License |
|------|--------|---------|
| `{baseDir}/rules/semgrep-rules/` | [returntocorp/semgrep-rules](https://github.com/returntocorp/semgrep-rules) | LGPL-2.1 |
| `{baseDir}/rules/0xdea-rules/rules/` | [0xdea/semgrep-rules](https://github.com/0xdea/semgrep-rules) | AGPL-3.0 |

## Cross-Language (always include, no `--include`)

- `{baseDir}/rules/semgrep-rules/generic`
- `{baseDir}/rules/semgrep-rules/problem-based-packs`

## Per-Language Mapping

For each detected language, include the primary directory and any framework directories whose markers were found.

### Python — `--include='*.py'`

| Component | Path |
|-----------|------|
| Primary | `semgrep-rules/python/lang` |
| Crypto | `semgrep-rules/python/cryptography` |
| Django | `semgrep-rules/python/django` |
| Flask | `semgrep-rules/python/flask` |
| FastAPI | `semgrep-rules/python/fastapi` |
| SQLAlchemy | `semgrep-rules/python/sqlalchemy` |
| Requests | `semgrep-rules/python/requests` |

### Go — `--include='*.go'`

| Component | Path |
|-----------|------|
| Primary | `semgrep-rules/go/lang` |
| gRPC | `semgrep-rules/go/grpc` |
| Gorilla | `semgrep-rules/go/gorilla` |
| GORM | `semgrep-rules/go/gorm` |
| jwt-go | `semgrep-rules/go/jwt-go` |

### C / C++ — `--include='*.c' --include='*.cpp' --include='*.cc' --include='*.cxx' --include='*.h' --include='*.hpp'`

| Component | Path |
|-----------|------|
| Primary | `semgrep-rules/c/lang` |
| Memory safety (no `--include`) | `0xdea-rules/rules/c` |

The 0xdea ruleset covers both C and C++ and catches use-after-free, integer overflow, format-string bugs, and other low-level issues missing from the official set. Always include it when C or C++ is detected. It contains `.c` and `.cpp` patterns directly, so do **not** apply `--include`.

### JavaScript — `--include='*.js' --include='*.jsx' --include='*.mjs' --include='*.cjs'`

| Component | Path |
|-----------|------|
| Primary | `semgrep-rules/javascript/lang` |
| Browser | `semgrep-rules/javascript/browser` |
| Express | `semgrep-rules/javascript/express` |
| React | `semgrep-rules/javascript/react` |
| Audit | `semgrep-rules/javascript/audit` |

### TypeScript — `--include='*.ts' --include='*.tsx'`

| Component | Path |
|-----------|------|
| Primary | `semgrep-rules/typescript/lang` |
| Audit | `semgrep-rules/typescript/audit` |

(JS framework directories above also apply when relevant.)

### Rust — `--include='*.rs'`

| Component | Path |
|-----------|------|
| Primary | `semgrep-rules/rust/lang` |

### C# — `--include='*.cs' --include='*.cshtml' --include='*.razor'`

| Component | Path |
|-----------|------|
| Primary | `semgrep-rules/csharp/lang` |
| .NET | `semgrep-rules/csharp/dotnet` |
| Razor | `semgrep-rules/csharp/razor` |

## Validating a Directory

Optional sanity check (no network — operates on local files):

```bash
semgrep --metrics=off --validate --config "{baseDir}/rules/semgrep-rules/python/lang"
```
