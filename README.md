# govulncheck-filter

Enforces a **time-boxed allowlist** over `govulncheck` JSON output.

Each allowlist entry acknowledges one vulnerability in one module, optionally
until a `review` date. The filter fails the build when:

1. an entry's `review` date is **more than `-max-future-days` (default 30)** in
   the future — acknowledgements can't be parked indefinitely;
2. an entry's `review` date is **in the past and the vulnerability is still
   called** — the grace period ended but the code is still vulnerable;
3. a **fixable** called vulnerability is allowlisted **without a `review` date**
   — if a fix exists you must commit to a remediation deadline;
4. a **called vulnerability has no allowlist entry** for its module.

Only *called* vulnerabilities count (govulncheck's reachable-symbol signal);
imported-but-uncalled findings are ignored. Scoping is `(id, module)` with a
`reason`, compatible with `.govulncheck-ignore.yaml`.

The `review` date is **required only for fixable vulnerabilities** — there is no
deadline to commit to when no fix exists. It is optional (but welcome) for
unfixable ones, and **whenever a date is present it is always honoured**: rules
1 and 2 apply regardless of fixability or `-ignore-unfixable`.

`-ignore-unfixable` only affects **unlisted** vulnerabilities: an unlisted
called vulnerability with no fix available is reported as a warning instead of
failing (there is nothing to remediate). Fixable unlisted vulnerabilities still
fail.

## Usage

Let the filter run govulncheck for you (recommended — no pipe, so `set -o
pipefail` can't trip on govulncheck's exit code, and the filter owns the result):

```sh
govulncheck-filter -invoke -- ./...
```

`-format json` is added automatically. Everything after `--` is passed straight
to govulncheck.

Or pipe existing JSON in:

```sh
govulncheck -format json ./... | govulncheck-filter
```

By default the allowlist is the nearest `.govulncheck-ignore.yaml`. The lookup
walks up from the current directory (or `-C <dir>`), checking each level, and
**stops at the first directory containing a `go.mod`** (the module root is the
ceiling). If no allowlist is found there, it is treated as empty — no exceptions,
so any called vulnerability fails. Reaching the filesystem root without a
`go.mod` is an error.

Output has three parts:

1. **Details** — for every finding reached in code (including acknowledged
   ones), the govulncheck advisory context: summary and details, more-info URL,
   affected and fixed versions, example call traces, plus this tool's review
   date and reason when the finding is allowlisted.
2. **Status list** — one concise `OK`/`WARN`/`FAIL` line per finding.
3. **Summary** — the one-line verdict (`PASS` / `FAILED: N`).

Under `-github-annotations` the details section is wrapped in a collapsible
`::group::` so the status list and summary stand out, each finding also gets a
`::error`/`::warning` annotation on its `go.mod` require line, and a final
non-line-pinned annotation reports the overall verdict (`::notice` when clean).

Exit codes: `0` pass, `1` policy violation, `2` usage/parse/govulncheck error.

Flags:

- `-allowlist <path>` — explicit allowlist path (overrides the default lookup; must exist)
- `-C <dir>` — directory to start the module-root search from (default: cwd)
- `-invoke[=<binary>]` — run govulncheck directly (default binary `govulncheck`, or name it: `-invoke=/path/to/govulncheck`); pass its args after `--`
- `-ignore-unfixable` — report *unlisted* called-but-unfixable vulnerabilities as warnings instead of failing
- `-github-annotations` — also emit GitHub Actions `::error`/`::warning` annotations anchored to the offending module's `require` line in `go.mod`
- `-warn-only` — report policy violations as warnings and exit 0 instead of failing (annotations, if enabled, are emitted at warning level)
- `-input <path>` — govulncheck JSON (default: stdin)
- `-max-future-days <n>` — future window for review dates (default 30)

In GitHub Actions, `-github-annotations` surfaces each finding inline on the
`go.mod` line that pulls in the vulnerable module:

```sh
govulncheck-filter -invoke -github-annotations -- ./...
```

## Allowlist format

```yaml
allow:
  - id: GO-2024-1234
    module: golang.org/x/net
    review: 2026-08-10   # YYYY-MM-DD; required if the vuln is fixable, optional otherwise
    reason: awaiting upstream fix, tracked in OGE-9999  # optional
```
