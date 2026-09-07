# Offline parser qualification (A1)

This research package measures a pinned `tree-sitter-bash` candidate against a
pinned `unbash` differential oracle. It does **not** enable parsing in the live
Gatekeeper, authorize parser-informed approval, add a production dependency, or
establish a supported operator runtime. Installed Stage 1 remains
`PARSER_UNAVAILABLE` / `PARSER_STAGE1_NOT_QUALIFIED`.

## Isolation and provenance

`research/parser-qualification/environment.lock.json` pins the standalone
CPython build, Python wheels, Node runtime, and unbash tarball for macOS arm64
and Forgejo/Linux x86_64. Every source artifact is SHA-256 verified before the
native parser is imported. Artifacts and extracted runtimes stay outside the
repository and are never committed.

The macOS interpreter is the arm64 CPython 3.13.15 standalone build. The Linux
runner uses its x86_64-musl peer because the Forgejo host runner is Alpine. The
Linux Node runtime is the pinned Node.js unofficial-builds musl artifact; this
provenance difference is retained in the evidence rather than hidden. Package
licenses and provenance are recorded in the lock. Upstream sources are:

- [python-build-standalone](https://github.com/astral-sh/python-build-standalone)
- [tree-sitter](https://pypi.org/project/tree-sitter/)
- [tree-sitter-bash](https://pypi.org/project/tree-sitter-bash/)
- [Node.js](https://nodejs.org/en/about)
- [unbash](https://www.npmjs.com/package/unbash)

## Running the macOS arm64 qualification

Create a temporary directory, download the five `macos-arm64`/`any` artifacts
from the lock into an artifact directory using their exact `filename` values,
and verify each SHA-256. Extract Python, Node, and unbash into a second temporary
directory, then install the two local wheels with the standalone interpreter's
pip using `--no-index`.

Run the harness with explicit isolated executables:

```bash
<isolated-python> scripts/research/parser_qualification.py \
  --artifact-dir <verified-artifact-directory> \
  --platform macos-arm64 \
  --python <isolated-python> \
  --node <isolated-node> \
  --unbash-module <extracted-unbash>/dist/parser.js \
  --output-dir <temporary-report-directory>
```

The harness rejects fewer than 10,000 benchmark parses. The Linux equivalent
is the manually dispatched `Parser Qualification Research` Forgejo workflow;
it is intentionally absent from push and pull-request triggers.

## Bounds and failure interpretation

Each parser is a private persistent subprocess. The tree-sitter child imports
and constructs its parser before emitting a bounded readiness frame; cold
initialization is outside candidate timing. After readiness, the parent detects
a 5 ms per-request deadline that includes request/response framing and IPC.
Expiry detaches the child immediately and returns `PARSER_TIMEOUT` without
waiting for cleanup. A private asynchronous reaper gives that isolated process
group 50 ms to exit after SIGTERM, then reliably applies SIGKILL and waits for
the exact child. The detached child is never reused, and the next request must
construct a fresh parser. The timed-out request is never retried. The unbash
oracle retains its one-second framing deadline.

This is deliberately not a native-callback timeout claim. With the pinned
tree-sitter 0.26.0 macOS arm64 artifact, adding the supported
`progress_callback` to callable-input parsing caused the isolated process to
exit with SIGSEGV/139 even for a benign 54 KiB static corpus. Callable-input
parsing without that callback succeeded. The unsafe callback is therefore not
used; its result is retained in provenance and decision evidence.

The parent sends at most 64 KiB and binds every request/response to the UTF-8
byte length and SHA-256. Successful primary responses additionally enforce a
5 ms IR-traversal budget, 4,096 nodes, depth 64, 32 diagnostics, and a 16 KiB
serialized IR. Timeout, crash, malformed framing, parse error,
missing/incomplete syntax, unknown nodes, dynamic syntax, or any exceeded bound
is explicit `UNMODELED_OR_INVALID` evidence.

The known Linux crash seed is retained in the synthetic corpus from
[tree-sitter-bash issue #337](https://github.com/tree-sitter/tree-sitter-bash/issues/337).
Corpus strings are parsed only and never executed.

## Evidence and data boundary

Each platform run writes four mode-`0600` JSON reports outside the repository:

- platform latency (cold start, p50/p95/p99/max), threshold misses, failures,
  and RSS delta;
- case-level corpus outcomes and every complete/error/span/dynamic/crash/IR
  disagreement;
- artifact hash, version, license, and provenance inventory;
- an evidence-completeness decision record that always states
  `adoption_authorized=false`, `live_shadow_authorized=false`, and no policy
  effect.

Reports contain case identifiers, expected syntax facts, bounded byte spans,
closed classifications, counters, and timings. They contain no operational
audit command, source fragment, reserialized command, environment, cwd, pane,
model, tool text, or output. The raw command remains the sole approval,
execution, identity, hashing, and TOCTOU target. A later A2 decision is required
for any live qualified shadow or hermetic production runtime.
