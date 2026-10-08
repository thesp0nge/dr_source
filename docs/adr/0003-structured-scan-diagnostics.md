# ADR 0003: Structured Scan Diagnostics

Status: Proposed

## Phase 1 implementation note

`core/diagnostics.py` supplies frozen `ResolutionDiagnostic` and
`ResolutionSummary` values and a scan-owned `ScanDiagnostics` collector. Event
identity originally used language, lexically normalized source path, nullable
line/column, and syntactic call name; the source-span correction below adds end
coordinates. Candidate tuples retain the resolver's deterministic
order. Equivalent duplicates count once; inconsistent payloads at the same
identity raise `ValueError` without replacing the existing observation. Event
snapshots sort by identity with missing coordinates before numeric coordinates.
The summary contains only the total and four status counts; rates are deferred.

`Scanner` creates one normalized absolute project root, `ProjectIndex`, collector,
and frozen `AnalysisContext` per scanner lifecycle. Before indexing it calls
`prepare(context)` once for each plugin instance, including plugins registered
for multiple extensions. Preparation failure propagates explicitly before
indexing or analysis can proceed with an unprepared plugin. Python, Java,
JavaScript, PHP, and Ruby retain the context and obtain their visitor index from
it. Direct standalone analysis without preparation retains its previous
no-project-index behavior. `index()` and `analyze()` signatures are unchanged.

The base preparation hook is a no-op for simple plugins. As a temporary
third-party compatibility adapter, it injects the context's index if a legacy
`project_index` attribute exists. Built-in consumers override the hook and do
not use that adapter. Scanner no longer injects attributes during analysis.
Third-party plugins that override `prepare()` must manage their own context;
the adapter can be removed once legacy plugin migration is complete.

At the end of Phase 1, resolver recording and recursive context propagation
were deferred; ordinary scans produced zero diagnostic events. Output, persistence,
finding semantics, and resolution decisions are unchanged. A fresh Scanner
remains necessary for a new source snapshot, as required by ProjectIndex's
registration lifecycle.

## Phase 2 implementation note

Python, Java, and JavaScript emit events in their call visitors immediately
following the existing `_resolve_project_call()` decision. Each copies its
status, reason, and candidate tuple without another lookup. Lookup guards,
local-function handling, sink handling, framework handling, and depth limits
are unchanged. Python's structural-only pass still has no project index and
therefore does not gain project lookup merely through instrumentation.

Taint visitors accept an optional explicit `AnalysisContext`; prepared analyzers
pass their scan context and source file. Recursive visitors retain that exact
context and switch to the callee's file (or retain the current file for local
simulation). Context-backed visitors use its index, reject a conflicting legacy
index argument, and require a source file. Standalone legacy visitors can still
use the index argument without collecting diagnostics.

Event positions describe the actual call: one-based lines and zero-based UTF-8
byte columns, from Python AST positions or converted Tree-sitter start points.
Java retains its bare method name; JavaScript retains its exact dotted name;
Python retains the syntactic name before import narrowing.

The collector remains the sole deduplication owner. Inconsistent same-site
payloads raise `ResolutionDiagnosticConflict`, a `ValueError` subtype which
propagates through analyzer and Scanner error handlers instead of being logged
and suppressed. Tests cover real conflicting records and repeated recursive
visits, including traversal/registration-order independence.

The denominator is existing attempted project lookup, not all calls. Recognized
sinks, locally handled calls, Java framework sinks, and non-call source accesses
can bypass lookup. Assignment source/sanitizer recognition alone does not stop
the later call visitor from performing lookup. Characterization tests retain
existing attempts for `request.args.get`, Java `getParameter`, sanitizer calls,
Python `print`, Java `println`, and JavaScript `console.log`. No general external
library classifier was introduced. Across multiple security categories a call
can be a sink in one visitor and reach lookup in another; the collector counts
that source site once if any existing visitor attempts project resolution.

Findings, resolver decisions, logging, reports, and persistence are unchanged.
Scanner retains its existing diagnostics attribute; broader ScanResult exposure,
user-facing summaries, and rendering remain separate work.

## Source-span identity correction

Diagnostic identity now includes the complete call-expression span:
`(language, normalized file path, line, column, end_line, end_column, call_name)`.
Python records `ast.Call` start/end positions; Java and JavaScript record the
actual invocation/call node's Tree-sitter start/end points. Lines are one-based,
columns are zero-based UTF-8 byte offsets, and the end is exclusive. End fields
are optional for genuinely unavailable positions; `None` is the deterministic
fallback, with all available coordinates retained and conflict detection active.

This distinguishes nested/chained JavaScript calls sharing a start and empty
syntactic name. Event ordering uses the full identity, with missing coordinates
before present coordinates. No status, reason, candidate, node object identity,
source text, or traversal order participates in site identity. Exact duplicate
payloads still count once; conflicting payloads for the same full-span identity
still raise `ResolutionDiagnosticConflict`. There is no persisted-format or CLI
migration: diagnostics have not been exposed through those contracts. Resolution,
findings, recording boundaries, and metric classification remain unchanged.

## Resolution provenance implementation

`ResolutionDiagnostic.origin` is a required immutable `ResolutionOrigin` value
owned by diagnostics, not by `Resolution` or `ProjectIndex`. Status and reason
answer **how resolution ended**. Origin answers **which evidence supported the
attempt** under the current frontend semantics. It is an exclusive classification
with deterministic precedence, independent of final status:

1. `EXPLICIT_PROJECT_BINDING`: Python's recorded import binding identifies a
   known project module. This includes a missing target, ambiguous target,
   unsupported alias, or unsupported call form within that binding. An alias
   stays unsupported; provenance does not implement alias resolution.
2. `CANDIDATE_BACKED`: without explicit project binding, the actual lookup
   discovered one or more relevant same-language indexed symbols. A singleton
   name match is evidence, not proof of receiver or module binding.
3. `FALLBACK_PROBE`: neither positive project-binding evidence nor candidate
   evidence supported the attempt. This does **not** mean external library:
   unindexed project classes, unknown receivers, builtins, and libraries can
   all occupy this population.

Python uses the binding facts already consulted by its resolver and returns
`(Resolution, ResolutionOrigin)` from its internal attempt helper. The existing
`_resolve_project_call()` remains a Resolution-only adapter for direct callers.
The call visitor consumes the pair at its existing recording boundary. An
unsupported syntactic alias to an absent/non-project module remains unsupported,
with fallback provenance: recognizing an import is not proof of project ownership.
No extra candidate lookup is performed, including for rejected aliases. Supported
imports to absent modules retain their existing global fallback behavior.

Java and JavaScript classify from the actual language-scoped candidate tuple.
Java still uses bare method names; JavaScript still uses exact syntactic names,
including dotted/empty names. Neither infers explicit project binding from
imports, receivers, class/package names, or dotted syntax. Python's explicit
binding takes precedence even if target-file narrowing leaves zero candidates.
Future narrowing must preserve candidate evidence if it discards candidates;
current non-explicit paths do not have a separate narrowing stage.

Origin is payload, not source-site identity. Identical complete payloads
including origin deduplicate. Conflicting origins at one full-span source site
raise `ResolutionDiagnosticConflict`; no last-write-wins or extra site is created.
Recursive and detector-category revisits use the same invariant.

`ScanDiagnostics.summary()` retains the frozen status summary unchanged.
`origin_summary()` returns a frozen `ResolutionOriginSummary` with total,
`explicit_project_binding`, `candidate_backed`, and `fallback_probe` counts.
Both decompositions count exactly the same event population:

```text
total_project_resolution_sites = resolved + unresolved + ambiguous + unsupported
total_project_resolution_sites = explicit_project_binding + candidate_backed + fallback_probe
project_evidenced_sites = explicit_project_binding + candidate_backed
```

Project-evidenced sites are a grouping, not another origin and not all project
calls. No ratio, quality score, CLI rendering, persistence, ScanResult, finding
model change, or resolution behavior change is introduced. Internal event
constructors must now provide origin; existing status-summary consumers need
no migration. Diagnostics have no public persisted format to migrate.

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
    end_line: Optional[int]
    end_column: Optional[int]
    call_name: str
    status: ResolutionStatus
    reason: ResolutionReason
    origin: ResolutionOrigin
    candidates: Tuple[SymbolId, ...]
```

Language, normalized source file, source position, and syntactic call target
are needed to explain where an attempt occurred. Status and reason are copied
from the resolver's `Resolution`; diagnostics do not reinterpret them.
Candidate IDs preserve ambiguity evidence without retaining AST or tree-sitter
objects. Candidate order is the deterministic order supplied by the index or
language resolver. Nullable start/end coordinates accommodate frontends that do
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
(language, normalized file path, line, column, end_line, end_column, syntactic call name)
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
    def summary(self) -> ResolutionSummary: ...
    def origin_summary(self) -> ResolutionOriginSummary: ...
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
