# ADR 0001: Collision-safe project symbol identity and resolution

Status: Proposed

Date: 2026-09-16

Scope: Architectural recommendation only. This ADR does not implement an API,
change analysis semantics, or authorize a full semantic-analysis rewrite.

### Phase 1 implementation note

Phase 1 now stores `SymbolId -> FunctionDefinition`. Frozen IDs include language,
lexically normalized supplied file path, name, and an optional declaration
position (one-based line, zero-based UTF-8 byte column). Owner and signature remain
`None`. Python, Java, and JavaScript indexers supply source positions without
extracting ownership or resolving overloads. Original AST/source payloads and
definition file paths are preserved.

`find_candidates(name, language=None)` returns all matching definitions, ordered
by identity file path, position, language, and name. A nested name/language index
supports both filtered queries and the temporary name-only compatibility query.
`find_function(name)` returns the sole candidate or `None`; multiple candidates
produce a warning listing their identities and stating that inter-file analysis
is skipped. This intentionally replaces arbitrary last-writer selection and can
remove findings that depended on that selection. Existing visitors still use
name-only lookup, including its cross-language ambiguity, until Phase 2.

The four-argument registration form remains available for unique declarations.
Re-registering the same payload object under the same ID is idempotent; a different
payload for that ID raises `ValueError` instead of overwriting it. Use distinct
source positions for different declarations and a fresh index for a new parse or
changed source snapshot. Incremental source-unit replacement is not implemented.

Project-relative path ownership remains a future integration step: Phase 1 does
not change scanner construction or infer a project root. Callers must use a
consistent path basis. IDs are not promised to survive checkout relocation or
source edits. Structured resolution results and semantic binding remain deferred.

## Context

`dr_source/core/project_index.py` stores
`Dict[str, FunctionDefinition]`. Registration assigns `functions[name]`; the
definition contains a name, file path, parser-specific node payload, and language.
`find_function(name)` returns that dictionary entry or `None`. A duplicate name
produces a debug message and replaces the previous definition.

The characterization tests in `tests/core/test_project_index.py` demonstrate that
Python `execute` definitions in different files overwrite one another, and that
a JavaScript `execute` replaces a Python `execute`. Registration order determines
which definition survives. Scanner traversal is not explicitly sorted. Sorting
registration would make the winner reproducible but would still discard symbols.

Bare names cannot identify definitions across files/modules, classes, lexical
scopes, or languages. Java also permits multiple methods with the same name in
one class through overloading; even name plus argument count is insufficient for
equal-arity overloads. Repeated declarations in the same scope must remain
representable without assuming which declaration is effective at a call site.
That last question belongs to resolution and language semantics.

Current production callers are:

| Language | Registration | Resolution |
| --- | --- | --- |
| Python | `PythonAstAnalyzer.index` in `dr_source/plugins/python/plugin.py` registers top-level `FunctionDef` and `AsyncFunctionDef` by `node.name`, with file path, native AST node, and `python`. | `PythonTaintVisitor.visit_Call` in `dr_source/plugins/python/taint_visitor.py` passes the syntactic bare or dotted call name. |
| Java | `JavaAstAnalyzer.index` in `dr_source/plugins/java/plugin.py` recursively registers method declarations by bare name, with file path, Tree-sitter node/source bytes, and `java`. | `TaintVisitor.visit` in `dr_source/plugins/java/taint_visitor.py` passes the bare method name, excluding the receiver. |
| JavaScript | `JavaScriptAstAnalyzer.index` in `dr_source/plugins/javascript/plugin.py` recursively registers function declarations by bare name, with file path, Tree-sitter node/source bytes, and `javascript`. | `JavaScriptTaintVisitor.visit` in `dr_source/plugins/javascript/taint_visitor.py` passes a syntactic identifier/member path. |

All three visitors consult a local name dictionary before global lookup and bound
global simulation by depth. They check the returned definition's language only
after lookup. A wrong-language survivor can therefore hide a valid definition.
Their local dictionaries also need eventual scope-aware treatment; replacing the
global index alone will not solve every local collision.

Registration does not extract module identity, lexical ownership, or signatures.
Java and JavaScript retain syntax/source context from which some of these facts
can be extracted; Python registration already knows that its functions are
top-level. Parameters are present in the declaration syntax. These are available
syntactic facts, not established import bindings or receiver types.

Python does not currently register methods or nested functions globally.
JavaScript registers nested function declarations but not class methods or arrow
functions through this indexing routine. Index storage capability must not be
confused with frontend coverage. PHP and Ruby do not currently call these
registration or resolution methods.

No resolver supplies language, file/module, owner, or arity to `find_function`.
None performs complete import, alias, package, receiver-type, or overload
resolution. Dotted Python/JavaScript calls do not automatically match bare-name
registrations. The existing tests in `tests/test_inter_file_analysis.py` establish
successful flows through uniquely named targets, not semantic binding accuracy.

## Decision drivers

- Correctness and precision: retain every definition and avoid fabricated call
  edges or arbitrary target selection.
- Deterministic behavior: identical inputs must produce identical candidates,
  ambiguity diagnostics, and analysis decisions regardless of registration order.
- Explainability: record what evidence selected or excluded a candidate and what
  information remains unknown.
- Inter-file taint analysis: preserve successful existing flows while exposing
  uncertainty and any analysis coverage lost during migration.
- Incremental migration: small, testable changes to index storage and callers.
- Python 3.9 compatibility: use supported dataclasses and typing constructs;
  require neither newer Python syntax nor new dependencies.
- Language-specific semantics: retain native Python AST and Tree-sitter payloads;
  do not impose a universal AST or universal overload rules.
- Future scalability: indexed candidate retrieval, bounded work, and source-unit
  lifecycle management rather than repeated whole-project searches.
- Avoid premature compiler/type-system complexity: extract facts the frontends
  can establish before attempting sophisticated semantic resolution.

## Considered options

### Option A — Composite dictionary key only

A key such as `(language, file, owner, name, signature)` prevents many collisions
with little machinery and makes equality explicit. It is a useful identity
building block.

It does not answer how callers lacking owner or signature information retrieve
definitions. Optional unknown fields can still cause collisions, including
repeated declarations. Using a partial tuple as an exact key would confuse
unknown context with known absence. Adding ad hoc fallback searches would merely
move resolution policy into dictionary access. This option alone is insufficient.

### Option B — SymbolId + SymbolDefinition + secondary indexes

Canonical storage maps an immutable `SymbolId` to a `SymbolDefinition`; secondary
indexes map searchable facts to sets of IDs. Resolution uses those indexes and
language-specific evidence without changing the identity of a definition.

The illustrative fields `language`, optional `module`, optional `owner`, `name`,
and optional `signature` are useful semantic dimensions, but are not sufficient
as the final ID schema. Unknown modules/owners/signatures and repeated
declarations require an independent source declaration discriminator.

This separates storage correctness from resolution completeness and supports
incremental semantic enrichment. It costs extra types, index maintenance, and
memory. This is the recommended architecture, with a deliberately small initial
implementation.

### Option C — Multimap keyed by name

`name -> [FunctionDefinition]` preserves duplicates and exposes ambiguity with a
small change. It is useful as a transitional candidate index.

As a final canonical model it lacks durable definition references, explicit
identity, and convenient language/file/scope filtering. Lists also invite
first/last-element selection and duplicate registrations. A name multimap should
be a derived index over canonical IDs, not a second authoritative store.

### Option D — Full semantic/call graph redesign immediately

A compiler-like semantic model could represent imports, types, dispatch,
overloads, and call edges comprehensively. DRSource's current frontends and tests
do not justify that scope. It would combine storage changes with major analysis
changes, make regressions hard to attribute, and delay the immediate collision
fix. Defer it; collision-safe storage is useful without a complete call graph.

## Decision

Recommend Option B, using a small source-grounded identity and explicit candidate
resolution. The following are invariants and conceptual dimensions, not final
public field names or API signatures.

### Canonical symbol identity

An ID identifies a particular source declaration within an indexed project
snapshot, not a claim about which runtime callable a name denotes. Its foundation
is language, source-unit identity, and a deterministic declaration locator.

- Language is mandatory. Cross-language identity never arises accidentally from
  matching names.
- Source-unit identity uses a project-relative, lexically normalized file path
  within the index's project scope. Preserve case and avoid machine-specific
  absolute paths in IDs. Do not infer modules from basenames or collapse symlink
  aliases implicitly. The scanner/frontend must supply a consistent project root.
- The declaration locator distinguishes kind, name, lexical containment, and
  source occurrence. An enclosing declaration reference or scope path plus source
  span is sufficient to distinguish same-name declarations even when semantic
  ownership/signatures are unknown. Language frontends extract these facts.
- Do not use registration counters, object addresses, or process-randomized hash
  values as identity. If a declaration location cannot be established, report an
  indexing diagnostic rather than silently merging definitions.

Unknown ownership must differ from a known top-level declaration. Module/package
names, semantic owners, and resolved signatures can enrich definition metadata
without changing the identity of that same declaration within a snapshot.
Registration of the same declaration is idempotent; conflicting payloads for one
ID are diagnosed rather than resolved by insertion order. Reindexing a changed
source unit removes its previous definitions and secondary entries as one
consistent operation.

Source locations ensure collision safety now, but can shift after edits. This
proposal guarantees identity reproducibility for unchanged inputs, not permanent
identity across refactoring or line insertions.

### Canonical symbol storage

Store `SymbolId -> SymbolDefinition`. Definitions retain source provenance,
language, name/kind, known module/package and lexical/class ownership, parameter
facts, and parser-specific analysis payloads. Unknown semantic facts stay unknown.
Store raw syntax once where practical; secondary indexes reference IDs rather
than copying ASTs or source buffers. Registration must preserve definitions even
when no current call site can resolve them.

### Secondary lookup strategy

Start with `(language, name) -> set of SymbolId`; maintain a name-only view solely
for the temporary legacy adapter. Add `(language, source_unit, name)`,
`(language, module, name)`, and `(language, owner_or_scope, name)` indexes when
callers can use those facts. Module and owner keys must be qualified within their
language/project namespace, not ambiguous strings such as `Utils` alone.

Only maintain indexes justified by real queries. Enumerate returned candidates in
a documented canonical order using source path and declaration locator, never
insertion order. Ordering is for reproducible output, not target preference.

### Signatures and arity

Keep language-specific parameter facts separate from universal identity:
positional/keyword parameters, defaults, variadic parameters, and syntactic type
references where applicable. Unknown arity is not zero arity. A textual type name
is not a resolved type.

For Java, preserve distinct declarations for overloads of equal or different
arity, and retain parameter type syntax and varargs information. Source locators
prevent storage collisions before type resolution exists. Later overload
selection must account for resolved parameter types and applicable conversions;
argument count alone is at most a sound candidate filter under known conditions.
Do not generalize Java overload semantics to Python or JavaScript.

### Resolution results and ambiguity

Direct retrieval by a known ID can return one definition. Call-site resolution
instead returns an explicit result containing candidate IDs, status, evidence,
and completeness/diagnostic information. Never expose a bare list with an
implicit convention that the first entry is correct. Language constrains the
candidate query before any definition is selected.

## Resolution model

| Outcome | Meaning |
| --- | --- |
| Exact resolution | Evidence establishes a unique binding under the supported language model, with one definition and the binding rationale. |
| Candidate resolution | One or more definitions satisfy the available constraints, but binding evidence or coverage is incomplete. A singleton name match is not automatically exact. |
| Ambiguous resolution | Multiple candidates remain without a justified selection. Return all supported candidates in canonical order and explain missing or conflicting evidence. This is a distinct case of candidate resolution. |
| Unresolved call | No supported candidate is available. Explain whether it is absent, external, unsupported, or blocked by missing analysis; do not claim the runtime target does not exist. |

Conceptually, extract a call description, query within its language, apply only
justified binding constraints, and classify the result. Known lexical bindings
may establish precedence; file proximity alone may not. Preserve uncertainty when
imports, aliasing, dynamic behavior, or receiver types could alter a target.
Never strip qualifiers and claim that a bare-name match proves ownership.

If resource limits prevent complete enumeration, mark the result incomplete and
emit a diagnostic. A truncated set must not appear exact or justify choosing its
first candidate. Later multi-target propagation needs bounded work and an
explicit evidence policy; it is not implied by adding candidate storage.

### Available information by language

| Language | Usable current facts | Facts requiring frontend/resolver work |
| --- | --- | --- |
| Python | Language, indexed file, top-level function name, native AST location and parameters; call AST with arguments and syntactic bare/dotted name. | Passing caller file/scope context, indexing nested functions/methods, lexical binding and rebinding, imports and aliases, package layout, receiver types, decorators and dynamic bindings. |
| Java | Language, file, method name, declaration and call syntax, source positions, parameter syntax, syntactic receiver and arguments. | Extracting/passing class/package ownership, imports and receiver bindings, type inference, inheritance/dispatch, overload applicability and selection. |
| JavaScript | Language, file, declaration/call syntax, source positions, parameter syntax, identifier/member path and arguments. | Extracting/passing lexical ownership, indexing methods and other function forms, import/require/export and alias bindings, module boundaries, receiver/object identity and dynamic property behavior. |

These contexts are not all passed to the index today. Frontends must supply
available facts explicitly; the generic index must not learn parser-specific AST
walking. Syntax-derived owner extraction is an incremental step, not complete
receiver resolution.

### Taint-analysis policy during migration

Keep existing successful unique-target inter-file flows operational. A temporary
compatibility policy may simulate a single same-language name candidate as current
analysis does, but must identify that edge as a name-based candidate assumption,
not exact binding. Record the resolution basis in diagnostics/evidence without
changing security severity to represent uncertainty.

For ambiguous targets, do not choose one or silently merge their taint facts.
Initially decline that interprocedural simulation and emit a deterministic
diagnostic naming the call and candidates. Continue other analysis. This can lose
findings that an arbitrary former winner happened to produce; integration tests
and release notes must make the coverage change explicit. No clean scan claim
should conceal unresolved analysis coverage. A future policy for evaluating all
plausible targets requires separate precision, resource, and evidence decisions.

## Migration plan

Each phase is a separate reviewed implementation change with focused tests and
the complete suite on Python 3.9 and the CI matrix. This ADR changes none of them.

### Phase 1 — Identity and storage

Introduce canonical IDs/definitions and secondary name storage. Extract stable
source-unit and declaration locators in Python, Java, and JavaScript frontends;
leave their supported declaration kinds and parser payloads unchanged. Keep the
existing `register_function` call shape as an adapter if practical, forwarding
explicit frontend metadata through an additive registration path. Parser-specific
location extraction must remain outside the generic core.

Retain a temporary `find_function(name)` adapter: return the definition only when
the name bucket contains exactly one entry; return no target with an ambiguity
diagnostic otherwise. This cannot preserve last-writer behavior and must not try.
It preserves unambiguous behavior while deliberately removing arbitrary choices.
Its cross-language ambiguity limitation is explicit until Phase 2. Do not retain
a hidden legacy map that still overwrites definitions.

Replace the current last-writer characterization expectations with preservation
and explicit-ambiguity expectations when this behavior is implemented, preserving
the same collision scenarios. Keep existing unique-target inter-file tests green.
Add real frontend/Scanner collision integration tests, including a previously
selected vulnerable target beside a safe target, and assert the diagnostic and
coverage change. If diagnostics cannot be surfaced, Phase 1 is not ready to ship.

### Phase 2 — Language-aware candidate lookup

Introduce the structured resolution result and `(language, name)` candidate
query. Migrate all three taint visitors together to pass their known language,
handle ambiguity/unresolved results, and document singleton compatibility
assumptions. Keep defensive payload-language checks. Cross-language definitions
must no longer hide or make a valid same-language target ambiguous.

Deprecate name-only `find_function`; remove it after all callers migrate and
compatibility obligations are reviewed. Do not preserve it indefinitely as an
alternate source of resolution policy. The name-only secondary view can then be
removed if no legitimate query needs it.

### Phase 3 — File/module and ownership-aware resolution

Pass caller source-unit and lexical context. Extract definition ownership and
known module/package facts in each frontend. Add secondary indexes as those
facts become useful. Address local visitor dictionaries so they cannot bypass
global collision safety with unrelated same-name local definitions.

Add scope-correct nested/method registration incrementally with language-specific
tests; do not hoist every newly indexed declaration into globally callable scope.
Use known lexical bindings to narrow candidates, preserving ambiguity where
ownership or imports remain unknown. Same-file location alone is not proof of
visibility or call binding.

### Phase 4 — Language-specific semantic resolution

Add bounded, separately tested support for Python imports/aliases and packages,
Java receiver/class/package and overload resolution, and JavaScript module/export
and receiver/alias resolution. Promote candidate results to exact only when
supported evidence permits it. Retain explicit incomplete and unresolved results
for unsupported semantics. Complete compiler behavior is not a phase exit goal.

### Compatibility impact

| Component | Expected migration impact |
| --- | --- |
| `register_function()` | Temporary compatibility adapter; ultimately registration supplies explicit identity facts without changing AST ownership. Existing name/file/node/language data remains useful. |
| `find_function()` | Cannot retain its current semantics safely for duplicates. Transitional unique-only behavior plus diagnostics, followed by structured language-aware resolution and deprecation. |
| Python analyzer | Preserve top-level registration initially; add source identity/location, then scope/import metadata in later phases. |
| Java analyzer | Preserve method payloads; add declaration identity, then class/package and parameter facts. No immediate type solver. |
| JavaScript analyzer | Preserve function-declaration payloads; add identity, then lexical/module metadata. No automatic expansion of frontend coverage. |
| Taint visitors | Consume resolution status/evidence, pass known context, and stop relying on a single global winner. Later align local symbol tables with scope semantics. |
| Existing inter-file tests | Remain acceptance gates for successful flows and traces; add precise ambiguity/language cases alongside them rather than skipping or weakening assertions. |

The canonical store is no longer a bare-name dictionary. Any consumers of the
current public `functions` attribute must be audited and migrated explicitly.
No persistence, finding-model, plugin-contract, or knowledge-base format change
is required by this ADR; any later need for one requires its own design review.

## Testing strategy

Tests planned here are implementation requirements, not additions in this ADR.

| Scenario | Immediate implementation coverage | Later coverage |
| --- | --- | --- |
| Same language/name, different files | Phase 1: both IDs retrievable, name lookup ambiguous; real indexing/Scanner integration. | Phase 3–4: caller scope and import evidence select only justified targets. |
| Different languages, same name | Phase 1: both definitions retained. Phase 2: queries isolate language and preserve valid cross-file flows in mixed-language projects. | Explicit cross-language bridges only if separately designed. |
| Same method name in different classes | Phase 1: Java declarations retained independently, including two classes in one file. | Phase 3–4: ownership/receiver-aware selection; Python/JavaScript methods when those indexers support them. |
| Nested functions | Phase 1: existing JavaScript nested declarations have distinct identities. | Phase 3: lexical visibility/shadowing and Python nested indexing, without leakage into unrelated scopes. |
| Java overloads | Phase 1: retain different-arity and equal-arity/different-type declarations. | Phase 4: applicability, varargs and equal-arity type distinctions; remain ambiguous without sufficient types. |
| Registration order | Phase 1 onward: permutations produce equal IDs/candidate sets, ordered diagnostics, and analysis outcomes; include duplicate registration and reindex cleanup. | Repeat for every new index/resolution rule. |
| Ambiguity | Phase 1 adapter and Phase 2 structured results: no first/last winner; safe/vulnerable candidate pair records incomplete analysis. | Bounded candidate handling and any later multi-target evidence policy. |
| Unresolved calls | Phase 1: unknown name returns no target. Phase 2: explicit unresolved result/reason without crashes or fabricated edges. | Unsupported imports, dynamic receivers, and incomplete indexing/resource limits. |
| Existing successful inter-file flows | Every phase: Python, Java, JavaScript findings and cross-file traces preserved for supported unique-target cases. | Paired safe/unsafe and negative decoy definitions to test precision as resolution improves. |

Identity tests should verify metadata and direct ID retrieval, not just counts.
Integration tests must use real language indexing and call resolution. Resolution
tests must distinguish a singleton candidate from an exact binding. Files and
scan databases remain temporary; external services are unnecessary.

## Non-goals

- Complete Python import semantics.
- Complete Java type resolution.
- Complete JavaScript module resolution.
- Full call graph construction or whole-program type inference.
- AI-assisted resolution.
- A universal AST, a Security IR implementation, or new language support.
- Semgrep compatibility or adoption of another product's API/architecture.
- New persistence formats, findings schemas, dependencies, or knowledge-base rules.

## Risks and trade-offs

- **Memory:** preserving all definitions and secondary ID references consumes more
  memory than retaining one winner. Avoid redundant payload copies and speculative
  indexes; measure growth and bound analysis work without silently dropping symbols.
- **Complexity:** identity, metadata, and resolution results require invariants and
  consistent cleanup. Keep the initial model small and test index consistency.
- **Legacy coexistence:** adapters can become permanent or conceal ambiguity.
  Give them explicit semantics and removal criteria; no alternate last-writer map.
- **Incomplete resolution:** candidate sets are expected, not internal failures.
  Deterministic diagnostics explain the missing facts, but do not replace future
  semantic work.
- **False positives:** simulating an unrelated candidate or merging all candidates
  can invent taint paths. Even singleton name matches can be wrong; preserve their
  provisional status until binding evidence exists.
- **False negatives:** declining ambiguous calls may miss real flows. Make this
  coverage limitation visible and test it instead of hiding it behind success.
  Better ownership/import evidence should reduce both kinds of error.
- **Identity stability:** source anchors are reproducible within unchanged trees
  but shift under edits. Do not promise stable cross-revision fingerprints or cache
  validity merely because a `SymbolId` exists.

## Consequences

Definitions can coexist without loss, resolution outcomes become reviewable, and
language-specific semantic improvements can be tested independently of storage.
Registration order ceases to decide call targets. Work remains necessary in the
frontends and local scopes; the index alone does not establish semantic accuracy.

Canonical references provide a foundation for later call graph edges with explicit
resolution evidence, per-function summaries, and shared interprocedural dataflow.
Summary caching will additionally need body/ruleset/configuration invalidation;
symbol identity alone is not a cache key.

Symbol-based finding fingerprints can eventually use qualified semantic identity
and a documented fallback for ambiguous declarations. Stable fingerprints across
edits require additional design beyond source spans. A future Security IR can
reference symbols and resolution evidence while preserving parser-specific
frontends. None of these follow-on capabilities is implemented or guaranteed by
this ADR, and deterministic analysis remains the basis for every resolution fact.
