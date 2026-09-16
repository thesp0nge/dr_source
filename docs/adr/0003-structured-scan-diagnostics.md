# ADR 0003: Structured Scan Diagnostics

Status: Proposed

## Context

DRSource now has a common immutable `Resolution` result. Python, Java, and
JavaScript project-call helpers can report `RESOLVED`, `UNRESOLVED`,
`AMBIGUOUS`, or `UNSUPPORTED`, with a structured `ResolutionReason` and
deterministic candidate identities. The result is currently consumed locally by
visitors. The scanner has no structured record of those decisions.

`Scanner` owns a scan, a `ProjectIndex`, the selected files, and the plugin
indexing and analysis phases. It currently gives plugins the index during
`index()` and sets a plugin's `project_index` attribute dynamically before
`analyze()`. `AnalyzerPlugin` defines no scan-context lifecycle method. Python,
Java, and JavaScript analyzers construct visitors during `analyze()`; recursive
visitors are constructed inside taint simulation and currently receive the
shared index but no scan diagnostics service or explicit source-file context in
all languages.

Resolution warnings are emitted by the index or language visitors. Logs are not
stable machine-readable data, do not provide a scan summary, and cannot
reliably distinguish a missing candidate from a skipped unsupported form.

## Problem

The project needs trustworthy observability into inter-file resolution without
turning analysis diagnostics into vulnerabilities. A future summary such as
“resolved 124, unresolved 17, ambiguous 3, unsupported 2” must preserve the
reason and candidates for each decision and must remain deterministic when
recursive simulation revisits a call site.

The summary must not claim that DRSource understands a corresponding
percentage of all application calls. Framework, library, builtin, source,
sink, sanitizer, and local-function handling may intentionally complete before
project lookup. A syntactic call such as `os.system(...)` is not an unresolved
project call merely because it is not indexed as a project symbol.

## Scope and terminology

A **project resolution attempt** is one call-site decision for which a
language-specific resolver deliberately consults project symbols, either
through `ProjectIndex.resolve_unique()` or language-specific candidate
narrowing. Calls handled as sinks, sources, sanitizers, framework constructs,
builtins, external libraries, or local functions are outside this denominator
unless a resolver explicitly attempts project lookup for them.

A **resolution event** is the structured result of one such attempt, together
with its source location and language. Diagnostics are observations of
resolution decisions; they are not security findings.

## Decision drivers

The design must preserve correctness and semantic honesty of metrics, make
skipped analysis explainable, remain deterministic under recursive analysis,
couple the scanner and plugins as little as possible, work across language
frontends, support future scan services, and remain compatible with Python 3.9.
It must not require a full call graph or force every language to expose the
same syntax semantics.

## Considered options

### Collector ownership

**Global mutable collector.** Easy for recursive visitors to reach, but makes
parallel scans, tests, nested scans, and ownership impossible to reason about.
It also leaks state between scans.

**Collector inside `ProjectIndex`.** Convenient for index lookups, but couples
generic symbol storage to language-specific source locations and scan
lifecycle. It cannot correctly record attempts resolved by Python import
context after candidate discovery, and it makes one index responsible for
diagnostics that may not represent a lookup at all.

**Per-visitor collectors.** Simple constructors, but recursive visitors create
fragmented summaries and require an error-prone merge protocol.

**Explicit scan-scoped collector.** The scanner owns one collector for one scan
and passes the same object through analyzers and recursive visitors. This gives
clear lifetime, deterministic finalization, and no hidden global state. This is
the selected ownership model.

### Plugin and context propagation

**Option A — Continue setting analyzer attributes dynamically.** This is the
current pattern for `project_index`. Extending it with optional attributes such
as `diagnostics` would create another implicit `hasattr()` contract and make
plugin capabilities difficult to discover or validate.

**Option B — Extend `AnalyzerPlugin` with an explicit lifecycle method.** Add a
small method such as `prepare(context)` with a default implementation. Scanner
calls it once before indexing and analysis. Plugins receive an explicit
`AnalysisContext`, while existing third-party plugins can remain operational
during migration. This is the preferred direction.

**Option C — Pass context to every `index()` and `analyze()` call.** This is
explicit, but changes the public plugin contract and every implementation at
once. It also does not by itself solve recursive visitor propagation.

**Option D — Store diagnostics in `ProjectIndex`.** This avoids another
argument, but violates the boundary between symbol storage and scan services,
and loses language-resolver context. It is rejected.

## Proposed diagnostic event

Introduce a small immutable event, conceptually:

```python
@dataclass(frozen=True)
class ResolutionDiagnostic:
    language: str
    file_path: str
    line: Optional[int]
    column: Optional[int]
    call_name: str
    status: ResolutionStatus
    reason: ResolutionReason
    candidates: Tuple[SymbolId, ...]
```

Language, normalized source file, source position, and syntactic call target
are needed to explain where an attempt occurred. Status and reason are copied
from the resolver's `Resolution`; diagnostics do not reinterpret them.
Candidate IDs preserve ambiguity evidence without retaining AST or tree-sitter
objects. Candidate order is the deterministic order supplied by the index or
language resolver. A nullable line or column accommodates frontends that do
not have a usable position for a particular call, but an event should not be
created without a source file when the resolver is operating on a project
source unit.

The event must not contain free-form log text or a parser node. Human-readable
messages can be rendered later from these fields.

## Event identity / deduplication

Initial scan metrics count **unique project-resolution call sites**, rather than
raw attempts. Recursive simulation may revisit the same source call while
following multiple taint paths; counting each visit would make totals depend on
recursion order and data-flow details. The deterministic event identity is:

```text
(language, normalized file path, line, column, syntactic call name)
```

The collector keeps one event per identity. If the same site is encountered
again with an equivalent result, it is ignored. If repeated visits produce
different results, the collector must apply a deterministic policy, such as
retaining the first result after sorting all observations by their stable
fields, and expose that conflict for follow-up testing. The preferred Phase 1
implementation is to require resolver decisions for a site to be stable and
reject conflicting duplicate records rather than silently merge them.

This identity is intentionally a call-site identity, not a complete execution
context. It cannot distinguish the same call reached through different callers
or taint paths; that distinction belongs to future data-flow diagnostics.

## Collector model

Use an explicit scan-scoped `ScanDiagnostics` owned by `Scanner`:

```python
class ScanDiagnostics:
    def record_resolution(self, event: ResolutionDiagnostic) -> None: ...
    def resolution_events(self) -> Tuple[ResolutionDiagnostic, ...]: ...
    def summary(self) -> Mapping[str, int]: ...
```

The collector is created at scan start, lives until scan completion, deduplicates
by event identity, and exposes immutable, deterministically sorted events after
collection. It has no global state and is not persisted in the first phase.
Recursive visitors receive the same instance. The scanner may retain it on its
scan state after completion, but rendering and persistence remain separate
concerns.

## Scan summary semantics

The initial summary contains:

```text
total_project_resolution_sites
resolved
unresolved
ambiguous
unsupported
```

The four status counts sum to the total number of unique recorded project
resolution sites. Optional breakdowns by language and `ResolutionReason` are
useful and deterministic, but should be added only after the core counts are
tested.

If a ratio is exposed, call it `project_resolution_rate` and define it as:

```text
resolved / total_project_resolution_sites
```

when the denominator is non-zero. It means “the fraction of attempted project
resolution sites resolved exactly.” It must never be presented as “83% of
application calls resolved” because DRSource does not enumerate every
application call or claim to understand external and local calls uniformly.

## Plugin lifecycle / AnalysisContext decision

Introduce a small explicit context for the scanner lifecycle:

```python
@dataclass
class AnalysisContext:
    project_index: ProjectIndex
    project_root: str
    diagnostics: ScanDiagnostics
```

`Scanner` creates it once, with its normalized analysis root and collector, and
calls an explicit `AnalyzerPlugin.prepare(context)` before indexing. The base
plugin contract should provide a no-op default for compatibility. Language
plugins may retain a reference to the context and use it when constructing
visitors; this is an explicit capability, not a dynamic `hasattr()` protocol.
The existing index argument to `index()` can remain during the migration and
later be adapted to context when the wider plugin contract is ready.

This is a small context object, not a service locator: it contains only
scan-wide services already shared by the current lifecycle. New services should
be added only with an explicit architectural decision.

## Language-resolver integration

Each resolver records exactly once, immediately after its structured decision is
made, through a shared helper that receives the current file and call node
location:

1. Python records the result of its project-call helper after local, sink,
   source, and sanitizer handling has been excluded. Its import-aware
   narrowing remains in the Python frontend.
2. Java records the result of its bare-name project helper after local and
   framework handling.
3. JavaScript records the result of its exact syntactic-name project helper;
   dotted names remain subject to its current semantics.

The resolver, rather than `ProjectIndex`, owns the recording point because it
knows whether a lookup was actually attempted and has the language-specific
source location. A wrapper can centralize event construction, but it must not
perform a second lookup or reinterpret the status.

## Recursive propagation

When `app.py -> service.py -> helper.py` creates child visitors, each child
receives the same `AnalysisContext` and therefore the same collector. The child
updates only its current file and recursion state. Events from all files belong
to one scan and are deduplicated by their own source identities. A new
collector per child is explicitly prohibited.

## Migration phases

### Phase 1

Introduce `ResolutionDiagnostic`, `ScanDiagnostics`, `AnalysisContext`, and the
explicit plugin preparation hook. Do not change CLI output, findings, or
resolution behavior. Add unit tests for event immutability, identity,
deduplication, ordering, and summary arithmetic.

### Phase 2

Record Python, Java, and JavaScript resolver outcomes at their existing project
lookup boundaries. Pass current file and source position explicitly to visitors
and recursive children. Add tests proving external/library and local calls are
not falsely counted, and that recursion shares one collector.

### Phase 3

Expose the completed summary and immutable event view through `Scanner` or a
future `ScanResult`. Add integration tests for language and reason breakdowns,
ambiguous candidates, unsupported bindings, and deterministic repeated scans.

### Phase 4

Optionally render summaries in CLI or reports and evaluate persistence. Any
SARIF or database representation requires a separate design because diagnostics
are not vulnerabilities.

## Testing strategy

Tests must verify one event per unique project-resolution call site, no double
counting during recursive simulation, deterministic event ordering, and exact
status/reason and candidate preservation. They should cover language breakdowns
and repeated registration or traversal orders. Fixtures must demonstrate that
external-library calls, source/sink calls, framework calls, and local
functions are not automatically recorded as unresolved project calls. Tests
should also verify that a missing, ambiguous, or unsupported resolution does
not become a `Vulnerability`.

## Non-goals

This ADR does not define metrics for all program calls, coverage or quality
scoring, CLI redesign, SARIF diagnostics, SQLite persistence, call-graph
construction, function summaries, additional language-resolution semantics, or
AI features.

## Risks and trade-offs

Call-site deduplication provides user-meaningful counts but hides repeated
resolution through distinct taint paths. Stable source identity depends on
normalized paths and parser positions, which can change when files move or are
edited. Explicit context plumbing increases constructor and plugin migration
work, while dynamic attributes are easier short term but less reliable.

Some frontends may lack precise columns or may encounter conflicting decisions
for one site; rejecting inconsistent duplicates is safer than silently making
counts traversal-dependent. Keeping diagnostics separate from findings adds a
second data model, but prevents ambiguity from being misreported as a security
issue. Avoiding persistence initially limits historical comparisons while
keeping the first implementation small and trustworthy.

## Consequences

DRSource gains deterministic, explainable visibility into the resolution work it
actually performs. Recursive analysis shares one auditable scan record, and
language-specific resolvers can evolve without making the generic index own
diagnostic policy. Future summaries, debugging output, and optional reporting
can consume structured events without parsing logs. The metrics remain honest:
they describe attempted project/inter-file resolution sites, not the fraction
of all calls in an application that DRSource understands.
