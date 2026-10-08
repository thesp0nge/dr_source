# ADR 0004: A detached ScanResult boundary

Status: Proposed

Date: 2026-10-08

Scope: Design only. This ADR adds no runtime API or behavior. Investigation is
based on `324413a244704f7218704913b0ba701e502a3a30`, with 185 passing tests,
package version `0.171.0`, and capability work targeting `0.172.0`.

## Context

[ADR 0001](0001-project-index-symbol-identity.md) separates source symbol identity
from resolution. [ADR 0002](0002-structured-call-resolution.md) supplies structured
resolution decisions. [ADR 0003](0003-structured-scan-diagnostics.md), including
its implementation notes, defines scan-owned resolution events, complete source
spans, conflict invariants, and provenance. These execution services now exist,
but `Scanner.scan()` still implicitly returns `None`.

Library consumers inspect Scanner's mutable attributes. The production CLI goes
further: after scanning it reads findings back from SQLite before displaying or
exporting them. A result value can separate completed observations from execution
without changing indexing, analyzers, resolution, or database formats.

## Problem

Scanner is both executor and result container. Its public-looking fields mix
inputs, partially accumulated state, final observations, and database identifiers.
Consumers cannot receive a completed result without retaining the executor, and
current reporting depends on successful persistence of findings. A tuple wrapping
`all_findings` alone would retain mutable objects owned by plugins/Scanner.

The next boundary should support library use, deterministic tests, diagnostic
inspection, reporting, benchmarks, and eventual service execution. It must not
suggest that a normal return proves complete analysis or successful persistence.

## Decision drivers

- Preserve existing findings, resolution decisions, diagnostic populations, and
  transitional database behavior.
- Return a small typed snapshot with no execution-service references.
- Make ordering, equality, copy isolation, and metric denominators explicit.
- Preserve existing `Vulnerability` objects without redesigning the finding model.
- Expose structured events, not only summaries or a misleading quality score.
- Keep Python 3.9 compatibility and avoid dependencies or a framework rewrite.
- Document deliberate public API changes under [versioning.md](../versioning.md).

## Current Scanner responsibilities

Investigation covered `core/scanner.py`, `cli.py`, `core/db.py`, `api.py`,
`core/context.py`, `core/diagnostics.py`, both ASCII/SARIF reporters, scanner,
database, timeout, inter-file, import-resolution and diagnostic tests, and the
fixture audit helper. Repository searches found the CLI as the production
`Scanner.scan()` caller; test callers and the investigation helper also ignore
the return and inspect Scanner state.

| Classification | Current state/responsibility | Result treatment |
| --- | --- | --- |
| Input/configuration | `target_path`, `timeout`, `ignored_dirs`, `ignored_extensions` | Remain executor/request inputs. |
| Execution setup/state | `extension_map`, plugin instances, `_prepared_plugins`, `project_root`, `project_index`, `analysis_context`, `last_interrupt_time` | Excluded. Root currently provides language/index context, not a result identity. |
| Transient locals | `files_to_scan`, timer start, plugin findings, deduplication keys, dictionary conversion buffers | Excluded. Snapshot only final selected observations. |
| Final observations | `all_findings`, `num_files_analyzed`, `scan_duration`, collector's sorted events | Copy/derive result values; retain legacy fields during migration. |
| Mutable execution service with final observations | `diagnostics: ScanDiagnostics` | Return its immutable event snapshot, never the collector. |
| Persistence-specific | `db`, `scan_id`, database path/project name, stored rows and summary writes | Remain outside core result. |

Important lifecycle details:

- Construction opens/creates the SQLite database and loads plugins. `scan()`
  calls `start_scan()` before timing, collection, and plugin preparation.
- It collects files, prepares each plugin instance once, indexes, analyzes,
  deduplicates findings, converts them to dictionaries, stores them, assigns final
  Scanner fields, and updates the database summary. Preparation failures escape.
- `os.walk` directories/files and discovered entry points are not explicitly
  sorted. Findings retain first-observed order; exact deduplication uses
  `(file_path, line_number, vulnerability_type, message)` and keeps the first
  payload. Severity, plugin name, and trace are not part of that key.
- `num_files_analyzed` is `len(files_to_scan)`, including files whose indexing or
  analysis fails, times out, or is skipped after an interrupt. It is a selected
  file count, not a successful-analysis count.
- Duration uses `time.time()` after `start_scan()` through vulnerability storage
  and conversion, excluding construction/plugin discovery, the database start
  write, and the final summary update. It is neither pure analysis time nor the
  full caller-observed runtime.
- The CLI consumes `scan_id`, `num_files_analyzed`, `scan_duration`, and `db`;
  its dictionary findings come from `get_vulnerabilities_for_scan()`. Default
  export names include the sanitized database project name and scan ID.
- Tests read `all_findings` and diagnostics directly. `test_scanner.py` asserts
  database start/store/update calls and conversion; `test_db.py` exercises real
  SQLite; `test_analysis_context.py` checks preparation/context ownership and a
  repeated scan with mock plugins. Inter-file/import tests protect findings;
  diagnostic tests protect recursion, ordering, conflicts, and provenance.

## Considered options

| Option | Advantages | Costs/decision |
| --- | --- | --- |
| A: Continue mutable Scanner attributes | No migration or new types. | Retains lifetime coupling, accidental mutation, and persistence-dependent consumers. Reject as the destination. |
| B: Return a dictionary | Easy additive return. | Mutable/untyped shape, unclear ownership and equality, harder compatibility documentation. Reject. |
| C: Introduce immutable typed ScanResult | Small explicit boundary, detached observations, typed diagnostics and metrics. | Requires copy/ordering policy and staged migration. Recommend. |
| D: Generalized analysis-session/result framework now | Could accommodate backends, streaming, services and many diagnostic classes. | Speculative complexity and broad engine changes. Defer. |

## Proposed ScanResult model

Recommend `dr_source.core.scan_result` as the public import location when
implemented, containing `ScanResult` and `ScanMetrics`. The public value shape is:

```python
# Conceptual public surface; not an implementation.
@dataclass(frozen=True)
class ScanMetrics:
    files_selected: int
    duration_seconds: float = field(compare=False)

class ScanResult:
    findings: Tuple[Vulnerability, ...]  # Read-only defensive-copy property.
    diagnostics: Tuple[ResolutionDiagnostic, ...]
    metrics: ScanMetrics

    def resolution_summary(self) -> ResolutionSummary: ...
    def resolution_origin_summary(self) -> ResolutionOriginSummary: ...
```

ScanResult should use frozen storage with a private detached findings tuple,
a constructor accepting the three public values, and a read-only `findings`
property returning detached copies. The shape above describes the contract,
not three unrestricted mutable attributes. Construction establishes canonical
ordering and tuple containers; summaries are derived from events. No finding
count is stored; use `len(result.findings)` and retain a local findings snapshot
when repeatedly processing it.

Metadata decisions for the first implementation:

| Candidate | Decision |
| --- | --- |
| Target/project path | Omit initially. Caller retains its scan request; findings/events preserve their supplied paths. Empty results do not identify a target. Future persistence accepts target/request context separately. Do not confuse `project_root` with a file target. |
| Engine version | Omit initially; existing reporters obtain installed package metadata per versioning policy. This result is not a reproducibility manifest. Before transporting historical results between engine installations, design captured producer-version metadata so a reporter does not misattribute its own runtime version. Never hardcode the release target. |
| Database `scan_id` | Omit. Persistence-specific receipt, not semantic scan identity. |
| Start/end timestamps or generated UUID | Omit. No existing trustworthy execution timestamp pair or backend-independent identity needs this first API. Database and reporter timestamps are not scan bounds. |
| Project-resolution summaries | Derive through the two methods, retaining all events. No duplicated stored summary fields. |

## Immutability and determinism

Frozen dataclasses are only shallowly immutable. `Vulnerability` is a mutable
dataclass with a mutable `List[str]` trace. Do not freeze/change that public type,
convert its trace to a tuple, or silently expose the Scanner's objects.

Recommend effective immutability through defensive copies:

1. Copy each accepted finding and its trace into private result-owned storage at
   finalization, constructing the existing Vulnerability type from its declared
   fields. No arbitrary plugin payloads or parser nodes are retained.
2. Each `result.findings` access returns a tuple of fresh Vulnerability copies,
   including fresh trace lists. Consumers may edit these local copies; later
   reads, result equality, Scanner fields, and other consumers are unaffected.
3. Diagnostics and SymbolIds are already frozen scalar/tuple values and may be
   shared safely in a new immutable tuple. Metrics are frozen scalar values.

This keeps the existing finding model and makes the public result effectively
immutable. Private storage is an implementation detail, not a supported mutation
API. Finding object identity between accesses is not promised. A detached tuple
exposing its mutable elements directly was considered but rejected: it would let
one consumer change the result another consumer observes.

Result equality compares private finding values, diagnostics, and the comparable
metrics. Duration is excluded. Equality expresses observation equality, not scan
identity, persistence success, equivalent rulesets, or cache validity. Explicitly
leave ScanResult unhashable; mutable Vulnerability internals are unsuitable hash
keys. Do not promise stable cross-revision fingerprints or checkout-relocation
identity.

No ProjectIndex, AnalysisContext, collector, plugin, database connection, AST,
or Tree-sitter node is exposed. A finalized result stays independent if Scanner's
legacy fields or collector are later mutated. Fresh Scanners remain the required
way to analyze a new source snapshot: index/context/preparation state currently
survives repeated `scan()` calls. Do not imply that returning a result fixes that
lifecycle; retain the existing mock-plugin repeat test without adding reuse or
concurrency guarantees.

## Findings semantics

Keep current deduplication, severity, message, plugin identity, source paths, and
trace contents. Do not drop, merge, or reinterpret findings while constructing a
result. The result's presentation order is canonical, independent of arrival
order **for the same retained finding values**:

```text
(file_path, line_number, vulnerability_type, message,
 severity, plugin_name, tuple(trace))
```

Use supplied paths and ordinary deterministic string/integer comparisons; do not
resolve symlinks or alter finding paths. Preserve trace step order. Canonicalize
only the copied result tuple, leaving the legacy list, database write order,
and current CLI behavior unchanged in Phase 1.

Consequently findings parity means value-for-value equality after applying this
ordering to the legacy list, not identical object identities or legacy discovery
order. Existing assertions against Scanner's fields remain unchanged.

Sorting cannot repair first-wins selection of differing payloads with the same
deduplication key, plugin nondeterminism, or source-order-sensitive frontend
behavior. Current tests establish traversal independence for selected fixtures,
not arbitrary plugins. Phase 1 must characterize this boundary with permuted
inputs and keep accepted payloads unchanged. Do not silently choose a different
duplicate winner or sort execution/plugin order to make results look deterministic;
any observed payload instability requires a separate correctness decision.
Do not claim unrestricted whole-engine determinism from result sorting alone.

## Diagnostics semantics

`diagnostics` contains only ResolutionDiagnostic events, equal to
`scanner.diagnostics.resolution_events()` at finalization. Keep the collector's
full-span identity/order, nullable coordinate fallback, candidate order, exact
payload, deduplication, and conflict behavior. Do not rerun resolution to expose
or summarize events.

These are all recorded resolver probes, not all application calls. Preserve:

- `EXPLICIT_PROJECT_BINDING`: known project binding evidence, even for missing
  or unsupported targets.
- `CANDIDATE_BACKED`: relevant same-language candidate evidence, not proof of
  exact receiver/module binding.
- `FALLBACK_PROBE`: no positive project evidence, not external-library ownership.

The summary methods use a shared pure reduction over snapshot events, returning
the existing frozen ResolutionSummary and ResolutionOriginSummary. Extract/reuse
collector counting logic when implemented so there are not divergent definitions.
No collector reference or precomputed mutable dictionary belongs in ScanResult.
Both independent decompositions and the project-evidenced grouping remain:

```text
total_project_resolution_sites = resolved + unresolved + ambiguous + unsupported
total_project_resolution_sites = explicit_project_binding + candidate_backed + fallback_probe
project_evidenced_sites = explicit_project_binding + candidate_backed
```

Resolution observations do not describe scanner/plugin execution failures.
Plugin discovery, indexing, analysis, parsing, and timeout failures are currently
mostly logged; some analyzers catch failures internally and return empty/partial
findings. Scanner can finish after skipped files or plugins. Missing targets can
also produce an empty completed scan after a warning. No structured completeness
or execution-success conclusion is available from the result proposed here.

Do not add `success=True`, invent execution-failure ResolutionDiagnostics, or
interpret empty findings/events as proof of complete safe analysis. Preparation
failures, analysis diagnostic conflicts, fatal database operations, and the
second interrupt can propagate; Phase 1 returns no result on those exceptional
exits. Not every indexing/plugin catch currently propagates every exception;
retain existing boundaries rather than generalizing them in this implementation.
A future execution-diagnostic field can be separately designed without broadening
this resolution-only tuple or introducing a generalized hierarchy now. Structured
failure/completeness observations are a separate priority before service users
can rely on unattended scan-success claims.

## Metrics semantics

Use `files_selected` rather than introducing another misleading successful-files
counter. It equals existing `scanner.num_files_analyzed` without changing that
legacy attribute or database column. It counts selected file paths once, not
plugin invocations; it is zero for an empty selection. Failure/timeout cases must
still preserve this count. Successful/failed/skipped counts are deferred because
current execution does not consistently collect those facts.

`duration_seconds` equals `scanner.scan_duration`, preserving its current timing
boundaries and clock for Phase 1. It is an observational wall-clock duration,
including some persistence work and excluding other overhead. Clock adjustments
can affect `time.time()`; do not promise monotonic benchmark precision or silently
clamp/redefine the value. A separately validated timer change may later use a
monotonic clock and explicit boundaries.

Mark duration `compare=False` in ScanMetrics so timing alone cannot make equal
observations unequal. Keep it accessible for human inspection/benchmarks, with
the limits above. Derive finding count from the findings tuple. Do not add rates,
coverage scores, speculative counters, or duplicated diagnostic counts here.

## Persistence boundary

Desired direction:

```text
Scanner -> ScanResult
Persistence backend <- ScanResult + request context
Persistence backend -> backend-specific receipt/identifier
```

| Option | Assessment |
| --- | --- |
| A: Keep persistence inside Scanner indefinitely | Lowest short-term disruption, but library scans remain tied to SQLite/filesystem writes and reporting can depend on storage. Reject as destination. |
| B: Return ScanResult and persist internally for now | Small additive change; existing CLI/history and tests keep working. Recommend for Phase 1. |
| C: Make Scanner pure and require explicit persistence immediately | Clean boundary, but constructor side effects, history/CLI defaults and failure handling would all change at once. Defer. |
| D: Add an orchestration/service layer above Scanner | Potential later owner of storage, timing and request context; unnecessary for the first return contract. Reassess when a second real backend/service requires it. |

Under B, keep database construction, start/store/update calls, row conversion,
scan IDs, and error policies unchanged. Return the snapshot only after the
existing final summary update succeeds. The duration remains the value measured
before that update, excluding the new snapshot-copy work. Storage failures
currently logged and continued do not change into new exceptions; start/summary
failures that escape still prevent a normal return. Return does not certify that
every finding was persisted.

Do not add persistence success flags or a core scan ID. Keep `scanner.scan_id`
for transitional CLI filenames/history, and later use a backend-specific receipt
outside ScanResult. An in-memory result should ultimately require no database,
but Phase 1 still does: a return type alone does not make Scanner pure.

Later, a storage adapter can consume the same result plus project/request
context and perform existing conversion without a schema change. Moving database
construction out of Scanner, making storage optional, and deciding transaction/
partial-write semantics require their own implementation and compatibility tests.
Diagnostics remain unpersisted unless separately designed.

## Reporting boundary

ASCII and SARIF currently accept dictionary rows, not Scanner objects. The CLI
creates that input by querying SQLite. ASCII selects vulnerability/file/line;
SARIF selects findings and tool metadata. SARIF currently creates timestamps at
report generation and unconditionally sets `executionSuccessful=True`; these
are not trustworthy scan execution facts supplied by Scanner. This ADR does not
change them or carry that success claim into ScanResult.

Phase 1 leaves both reporter signatures and CLI flow unchanged. Subsequently
migrate the fresh-scan CLI path to result findings/metrics with a small mapping
adapter for existing reporters, avoiding the database read-back. Capture one
`result.findings` snapshot per report. History/comparison and scan-ID-based
filenames continue using persistence-specific context/receipts. Keep dictionary
export shapes and rendering behavior until deliberately migrated.

Eventually reporters accept ScanResult directly. Historical DB-row reporting can
retain a separate adapter; old rows do not contain resolution diagnostics and
must not be represented as a complete reconstructed scan result without an
explicit missing-data policy. Reporting must not reinterpret findings or turn
resolution failures into security findings. Version attribution for transported
results and execution-success reporting need explicit follow-up designs, not a
reporter rewrite hidden inside Phase 1.

## API compatibility and migration

The future contract is `result = Scanner(...).scan()`. Returning a value is
additive for callers that ignore it, but code checking `scan() is None` changes.
Document this as an API change. During transition, legacy findings, counters,
diagnostics, scan ID and database access remain populated with existing semantics.

Once shipped, ScanResult, ScanMetrics, their documented constructor/accessors,
the findings tuple/value-copy semantics, diagnostics tuple, summary methods and
summary types, and `Scanner.scan()` return annotation are public. Exposed
ResolutionDiagnostic, resolution enums, and SymbolId payloads also become public
contracts through that API; the mutable collector/index do not. Prefer keyword
construction and document fields without promising dataclass internals or private
storage. Public import paths must be covered by implementation tests.

Follow `0.MINOR.PATCH` policy for future changes: public breaking changes require
an intentional MINOR release and migration documentation, not PATCH. Deprecation
and removal of Scanner's legacy result fields require release notes and migrated
callers; this ADR does not remove them. No stable serialized wire format is
promised by adding Python types. Equality is not a persistence identifier.

## Versioning/release implications

ScanResult is planned for `0.172.0` if implemented before that release cut. It is
a new public/core capability and a MINOR-level change under
[versioning.md](../versioning.md). If implemented after that cut, target the next
capability release according to the same policy.

Keep `pyproject.toml` at `0.171.0` during this design task and ordinary feature
implementation. Bump only at release preparation. Do not hardcode `0.172.0` as
runtime engine metadata. Add an `[Unreleased]` entry only after implementation,
not for this proposal, and do not create a `0.172.0` released section now.

## Testing strategy

Implementation acceptance requires focused result/scanner/diagnostic tests,
resolution/inter-file suites, the full suite, and `git diff --check`:

1. **Return contract:** `result = scanner.scan()` is a ScanResult on normal
   completion, including empty valid directories or no eligible files. Document
   current missing-target behavior separately; do not imply target validation.
2. **Findings parity:** compare every declared Vulnerability field and trace
   against canonically ordered legacy findings; preserve old list order and
   persisted payloads. Include differing trace/severity/plugin payloads sharing
   a deduplication key to characterize current first-wins behavior.
3. **Diagnostics parity:** exact event tuple equality with the collector;
   summaries match collector summaries, including empty and mixed populations.
   Retain both denominator equations and conflicting-origin rejection.
4. **Metrics parity:** `files_selected == scanner.num_files_analyzed` and
   `duration_seconds == scanner.scan_duration`, including timeout/plugin failure
   and empty scans. Controlled clocks should prove existing duration boundaries;
   do not rely on exact wall-clock timing assertions.
5. **Equality:** different durations with otherwise identical observations
   compare equal; findings, diagnostics or file count changes compare unequal.
   Result is unhashable; it is not a persistent identity or cache key.
6. **Immutability/isolation:** frozen fields and tuples reject reassignment/item
   mutation. Mutate original/legacy findings and traces, then copies obtained
   through result.findings, and verify subsequent result reads/equality are
   unchanged. Later collector records must not alter result diagnostics.
7. **Ordering:** permute identical retained finding values and filesystem
   traversal to verify canonical result order without altering legacy execution.
   Test diagnostic registration/recursive/category revisits. Do not weaken tests
   or change duplicate winners if an underlying payload instability appears.
8. **No execution internals:** the public result graph contains only expected
   Vulnerability copies, frozen diagnostics/identities, metrics and scalar data;
   no ProjectIndex, AnalysisContext, collector, plugin, database or parser nodes.
9. **Finding compatibility:** retain existing scanner, Python import and
   inter-file assertions and findings with recording enabled/disabled. Phase 1
   leaves CLI/reporting output and database read-back behavior untouched.
10. **Corpus compatibility:** rerun the same six independent factory-KB audits
    twice. Preserve 183 sites, 51 findings, all event identities/payloads, and
    status/origin distributions: 4 resolved, 179 unresolved; 1 explicit project
    binding, 3 candidate backed, 179 fallback. Do not reinterpret manual groups
    or change scan roots to obtain these numbers. Result diagnostics must be
    semantically identical to the collector audit, not merely equal in count.
11. **Persistence compatibility:** retain mocked start/store/summary assertions
    and real temporary SQLite round trips. Test empty scans, logged storage
    failure, escaping start/summary failure, preparation failure, and diagnostic
    conflict with current control-flow behavior; do not return partial results
    on paths that currently raise.

Tests must isolate database writes as existing conftest does and must not depend
on network, publication, or executing vulnerable fixture programs. Tests listed
here are required future work, not tests added or claimed to pass by this ADR.

## Migration phases

1. **Return snapshot, retain side effects.** Implement only the result/metrics
   boundary, canonical snapshot order, copy isolation and pure event summaries.
   Keep Scanner execution, legacy fields, database writes, CLI and reporters.
   No new persistence mode, execution diagnostic hierarchy or timer redesign.
2. **Migrate callers.** Adopt result values in library tests/audit and fresh-scan
   CLI/report adapters. Preserve history/comparison separately. Keep compatibility
   tests for legacy fields while documenting the new public return API.
3. **Deprecate executor result attributes.** After callers migrate, mark legacy
   findings/counters/collector access deprecated or internal in a deliberate
   MINOR-level API evolution. Keep execution-context propagation internal; do not
   conflate it with deprecating returned diagnostic values.
4. **Move persistence/reporting consumption.** Reporters and persistence adapters
   consume ScanResult, with separate request context and backend receipts.
   Remove scan-time database dependency only with an explicitly tested migration.
   Add an orchestration layer only if actual consumers justify it.

Each phase is separate scoped work. Do not combine all four into the first
implementation or commit this proposal as implemented behavior.

## Non-goals

This task implements no ScanResult/ScanMetrics, CLI rendering, persistence or
reporter rewrite, database schema, finding model, general diagnostic hierarchy,
call graph, function summaries, Security IR, AI features, language semantics,
concurrency, version bump, release automation, tags or publication. ProjectIndex
and AnalysisContext remain execution internals. No serializer or stable scan
fingerprint is designed here.

## Risks and trade-offs

- Defensive copying adds linear allocation at finalization and findings access.
  Consumers should retain one local tuple when iterating repeatedly. This is the
  price of effective immutability while preserving mutable Vulnerability objects;
  do not conceal the cost or redesign findings inside this patch.
- Canonical result order differs from legacy discovery order. This is a deliberate
  public presentation contract; Phase 1 leaves old consumers unchanged. Sorting
  cannot guarantee deterministic payload selection for arbitrary plugins.
- Public events/summaries increase the compatibility surface. Avoid speculative
  metadata and promise only documented semantics, not dataclass serialization.
- Transitional database side effects restrict true in-memory use. Keeping them
  makes adoption small but is not the final library boundary.
- Empty/partial results lack structured execution completeness. Services must not
  treat them as clean-scan guarantees. Better execution diagnostics are separate
  work, and existing unconditional SARIF success metadata is a known limitation.
- No captured target/version/timestamps means the first result is an immediate
  in-process observation, not a self-identifying historical artifact. Add producer
  metadata deliberately before cross-installation transport or archival use.
- Reusing a Scanner for changed sources remains unsafe; returning a detached
  result must not suggest incremental indexing or reusable sessions.

## Consequences

Recommend Option C for the return model and persistence Option B for the next
implementation. A small Phase 1 is ready to implement with the copy, ordering,
equality and failure-boundary tests above. It creates a public result boundary
without changing analysis semantics or requiring a generalized session engine.

Callers gain an independently usable observation snapshot and resolution events.
They no longer need executor references to inspect those observations. Later
migrations can move reporting and persistence without changing language visitors.
The design deliberately does not promise pure scanning, complete execution
status, full finding-model immutability, historical version attribution, or
whole-engine determinism beyond the defined snapshot guarantees.
