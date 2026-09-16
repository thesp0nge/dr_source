# ADR 0002: Structured Call Resolution Outcomes

## Context

DRSource has two related operations that are currently represented by APIs with
different levels of information. `ProjectIndex` stores declarations and
provides `find_candidates(name, language=None)`, while legacy callers use
`find_function(name, language=None)`. The latter returns a
`FunctionDefinition` only when exactly one candidate exists and otherwise
returns `None`. A warning is emitted for multiple candidates, but no value
identifies whether `None` means no declaration, ambiguity, or an unsupported
call.

Python resolution now adds language-specific import context. It can bind an
unqualified call to a selected module and can reject unsupported aliases. Java
and JavaScript currently perform language-scoped name lookup and have no
module or receiver resolver. These paths all have legitimate outcomes that
are not equivalent: a call may resolve exactly, have no candidate, remain
ambiguous, point through an explicit import to a missing symbol, or use a
syntax that the frontend does not support.

## Current limitations

The current behavior can be summarized as follows.

| Area/state | Current API return | Logging/diagnostic | Can caller distinguish reason? |
| --- | --- | --- | --- |
| ProjectIndex, zero candidates | `find_candidates` returns `[]`; `find_function` returns `None` | No warning from the index | No |
| ProjectIndex, one candidate | One definition from both APIs | None | Yes, by return value |
| ProjectIndex, multiple candidates | Candidate list; legacy lookup returns `None` | Warning naming count, language scope, and candidates | Only by separately discovering candidates or parsing logs |
| ProjectIndex, language-scoped zero/one/multiple | `[]`, one definition, or `None` respectively | Warning only for multiple | Zero and ambiguity both collapse to `None` in legacy callers |
| Python unique bare global | Python `find_function` returns one definition; visitor simulates it | None | Usually yes |
| Python ambiguous same-language global | `find_function(..., language="python")` returns `None` | ProjectIndex ambiguity warning | No through the return value |
| Python supported `from module import function` | Visitor filters Python candidates to the bound file; one target is simulated | Target ambiguity/miss warning when count is not one | Partly; visitor knows it was explicit, but returns no structured reason |
| Python supported `import module; module.function()` | Visitor resolves the recorded module binding, then filters to its file | Warning for missing or ambiguous target | Partly |
| Python imported module exists, symbol missing | Zero target-file candidates; no simulation | Python “ambiguous or unresolved” warning | Only through logs |
| Python unsupported alias binding | No fallback lookup | “Unsupported or unresolved Python import binding” warning | Yes only informally through the log |
| Python unresolved dotted call | No matching exact language-scoped candidate in the usual case | Often no warning; unsupported forms may warn | No |
| Python same-module ambiguity | More than one target-file candidate; no simulation | Python ambiguity/unresolved warning | Only through logs |
| Java unique global method | Java `find_function` returns one definition and visitor simulates it | None | Usually yes |
| Java ambiguous same-name methods | Legacy lookup returns `None` | ProjectIndex ambiguity warning | No through the return value |
| Java unresolved receiver/member call | Receiver is not semantically resolved; lookup may find no exact bare method | Usually no resolver-specific diagnostic | No |
| JavaScript unique global function | JavaScript `find_function` returns one definition and visitor simulates it | None | Usually yes |
| JavaScript ambiguous same-name functions | Legacy lookup returns `None` | ProjectIndex ambiguity warning | No through the return value |
| JavaScript unresolved dotted/member call | Dotted text is looked up as an exact name; normally no candidate | Usually no resolver-specific diagnostic | No |

Python's import context is owned by the Python frontend, not by
`ProjectIndex`. During recursive simulation the visitor carries the callee's
file, so the callee's bindings are used. Java and JavaScript visitors pass the
language to the index but still receive only a definition or `None`.

## Decision drivers

The replacement must preserve deterministic inter-file findings, distinguish
expected analysis outcomes, explain skipped calls, remain compatible with
Python 3.9, and permit incremental migration. It must keep language-specific
semantics in language frontends, avoid silently selecting an arbitrary
candidate, and avoid introducing a compiler-scale call graph before the
available facts justify one.

## Considered options

### Option 1: Continue returning `Optional[FunctionDefinition]`

This has minimal migration cost and preserves every existing caller. It cannot
represent ambiguity, unsupported syntax, or an explicit import that points to
no declaration without out-of-band logs. Callers must repeat candidate
discovery or interpret warning text, which is fragile and difficult to test.

### Option 2: Raise exceptions for ambiguity and unresolved calls

Exceptions make the distinction visible, but these are normal static-analysis
outcomes rather than exceptional failures. They would require broad control
flow changes and risk aborting or obscuring otherwise useful scans.

### Option 3: Return a small immutable `Resolution`

A value object can carry status, the selected identity, all candidates, and a
structured reason without making the index a language resolver. It is easy to
adapt around the current APIs and supports deterministic diagnostics. The
trade-off is a new type and a period in which old and new APIs coexist.

### Option 4: Build a complete call-graph/resolution framework immediately

This could eventually model imports, receivers, overloads, and call edges, but
it is disproportionate to current frontend facts. It would expand the change
surface, increase false-resolution risk, and make incremental validation harder.

## Proposed decision

Introduce a small immutable result for language-specific resolution:

```python
class ResolutionStatus(Enum):
    RESOLVED = "resolved"
    UNRESOLVED = "unresolved"
    AMBIGUOUS = "ambiguous"
    UNSUPPORTED = "unsupported"


class ResolutionReason(Enum):
    NONE = "none"
    NO_CANDIDATES = "no_candidates"
    EXPLICIT_IMPORT_MISSING = "explicit_import_missing"
    AMBIGUOUS_CANDIDATES = "ambiguous_candidates"
    UNSUPPORTED_IMPORT = "unsupported_import"
    UNSUPPORTED_CALL = "unsupported_call"


@dataclass(frozen=True)
class Resolution:
    status: ResolutionStatus
    target: Optional[SymbolId]
    candidates: Tuple[SymbolId, ...]
    reason: ResolutionReason
```

`RESOLVED` carries one canonical `SymbolId`; callers can retrieve the
corresponding definition from `ProjectIndex`. Candidate IDs, rather than AST
objects, keep the result immutable, compact, and independent of parser
payloads. The candidate tuple is always deterministic and is empty when no
candidate was discovered. `reason` is an enum (or a similarly closed
structured value), rather than free text; human-readable messages belong to a
diagnostic layer. `EXPLICIT_IMPORT_MISSING` is distinct from ordinary
`NO_CANDIDATES`, while both remain `UNRESOLVED`. Unsupported syntax is not
reported as an unresolved symbol.

Resolution is a decision over candidates, not candidate discovery. A future
resolver follows this contract: zero candidates produce `UNRESOLVED`, one
valid candidate produces `RESOLVED`, and more than one produces `AMBIGUOUS`.
It never selects by registration order. An explicit binding constrains the
candidate set before this decision.

## Boundary between ProjectIndex and language resolvers

`ProjectIndex` remains responsible for canonical `SymbolId` storage and
deterministic `find_candidates` retrieval, optionally scoped by language. It
does not parse imports, infer receivers, interpret packages, or produce a
language-independent call graph. `find_function` remains a compatibility
adapter during migration and must retain its current unique-only semantics.

Python, Java, and JavaScript frontends own their syntax and available context.
A future `resolve_call(...) -> Resolution` can share only small common facts:
the language, source file, syntactic call name, and candidates requested from
the index. Python may add its module/import binding context; Java may later add
receiver and overload context; JavaScript may later add module or object
context. This avoids a giant universal `CallContext` that pretends all
frontends expose the same semantics.

## Compatibility and migration strategy

1. Define the immutable result and reason values, plus an adapter that maps
   current candidate lists and legacy `None` outcomes without changing
   findings. Keep `find_candidates` and `find_function` intact.
2. Migrate Python's existing import-aware resolver first. Preserve its module
   filtering and recursive callee-file context, but return structured reasons
   for missing imports, unsupported aliases, and target ambiguity.
3. Migrate Java and JavaScript global lookup. Their current language-scoped
   candidate behavior remains unchanged; unresolved receiver/member forms are
   explicitly reported as unresolved or unsupported according to frontend
   capability.
4. Add a scan-level diagnostic collector and migrate callers away from
   parsing warning text. Only after all callers use structured results should
   the legacy unique lookup be deprecated and eventually removed.

Each phase keeps existing inter-file tests and successful findings as the
compatibility gate. No phase may turn ambiguity into an arbitrary selection.

## Diagnostics implications

Current warnings are useful for developers but are incomplete as a user-facing
record: zero candidates often produce no message, ambiguity is emitted by a
low-level index helper, and unsupported Python imports are mixed with missing
symbols in text. A `Resolution` object makes status, reason, and candidate IDs
available to a later scan-diagnostics collector. That collector could count
ambiguous, unresolved, and unsupported calls, attach source locations, and
render concise CLI/CI summaries while retaining detailed debug logs. The
resolution object itself should remain data, not perform logging, so repeated
visits do not create duplicate or order-dependent diagnostics.

## Testing strategy

Unit tests should cover zero, singleton, and multiple candidate sets in both
language-scoped and unscoped queries. Resolver tests should assert exact
status, reason, target identity, and deterministic candidate ordering for
Python imports, Java global methods, and JavaScript global functions. They
should also cover missing explicit imports, unsupported aliases, unresolved
dotted calls, and same-language ambiguity. Existing successful inter-file
flows remain regression tests, and registration-order independence must be
asserted. Diagnostics tests should verify that foreign-language candidates do
not appear after language scoping.

## Non-goals

This ADR does not implement more Python import semantics, Java receiver or
type resolution, JavaScript module resolution, call-graph construction,
function summaries, Security IR, a diagnostics subsystem, or AI features.

## Risks and trade-offs

The result type adds migration complexity and temporary coexistence with the
legacy APIs. Candidate tuples can retain more identity data than a single
definition, and incomplete language semantics will legitimately produce more
`AMBIGUOUS` or `UNRESOLVED` outcomes. Treating those outcomes explicitly may
expose missed inter-file flows that were previously hidden by arbitrary
behavior, while conservative unresolved results can still cause false
negatives. Structured reasons improve explainability but require each frontend
to classify its unsupported cases consistently.

## Consequences

Resolution decisions become deterministic, testable values rather than a
combination of `None` and log parsing. Future call-graph construction can use
resolved identities as edges, function summaries can be keyed by stable
symbols, and interprocedural dataflow can share explicit candidate and
ambiguity evidence. Stable symbol-based finding fingerprints and a later
Security IR also gain a clear boundary between declaration identity and call
resolution, while language-specific semantics remain in their frontends.
