# Resolution diagnostics denominator investigation

Audit of baseline `3fc9fb5e1d9c01408a71b419f0bc68c18684cf01` (152 tests),
using DRSource 0.171.0 and Python 3.9.6. The original investigation changed no
production code. Tables and snapshot below now reflect a source-span identity
correction based on baseline `6933aa0c79ab5444e8794bd393f339d8ef1c6525` (154 tests).
Resolution decisions, recording boundaries, security knowledge, finding output,
and semantic classifications are unchanged.

## Current semantics

`total_project_resolution_sites` counts unique **recorded resolver-site
identities**, not all calls, all project calls, or understood application calls.
An event is emitted immediately after the existing project resolver returns.
Identity is `(language, normalized file, line, column, end_line, end_column,
syntactic call name)`. It spans the complete call expression, with one-based lines,
zero-based UTF-8 byte columns, and an exclusive end. Unavailable coordinates remain
`None` as a deterministic fallback; conflicting same-identity decisions still fail.
Equivalent revisits across detector categories and recursive simulation count
once. Status/reason/candidates describe the existing decision, not the reason
for invoking project lookup or a proof that the target belongs to the project.

Each detector has its own sinks. A call handled as a sink by one detector can
reach project lookup in another. Assignment source/sanitizer recognition does
not stop the subsequent call traversal. Local handling and depth guards can
prevent attempts; neither constitutes a comprehensive inventory of local calls.
Python's structural pass has no project index and produces no such events.

The original audit found that distinct nested JavaScript calls shared an identity
when their extracted name and start coordinates matched. Complete source spans
now distinguish these calls without changing their names or resolver decisions.

## Identity correction rerun

The same six scans now produce **183 events instead of 180**. Python stays at 91
and Java at 39; JavaScript increases from 50 to 53. The difference is exactly
three restored unresolved/`NO_CANDIDATES`, zero-candidate JavaScript call sites:

| Fixture under `tests/test_code/javascript/` | Shared start | Distinct exclusive ends | Previous identities | Corrected identities |
| --- | --- | --- | ---: | ---: |
| `crypto_tests.js:5`, `.update(data).digest('hex')` chain | (5, 11) | (5, 48), (5, 62) | 1 unnamed | 2 unnamed |
| `crypto_tests.js:10`, `.update(data).digest('hex')` chain | (10, 11) | (10, 51), (10, 65) | 1 unnamed | 2 unnamed |
| `final_kb_tests.js:17`, `.toString(36).substring(7)` chain | (17, 18) | (17, 44), (17, 57) | 1 unnamed | 2 unnamed |

All previous event payloads are preserved when projected onto the old identity;
only those three identities split. The added rows inherit the original B
classification and evidence; no event is reinterpreted. The four resolved sites,
all candidate identities, 51 findings, and empty warning/error lists are
unchanged. The axios `.then(...)` chain still contributes one unnamed call.
The JavaScript regression verifies three calls on `crypto_tests.js:5` now yield
three events, including the unchanged named `crypto.createHash` call.

## Fixture methodology

Six independent project scans used the real `Scanner`, real indexing, real
language analyzers, and the unmodified factory knowledge base:

| Scan root under `tests/test_code/` | Files | Sites | Resolved | Unresolved | Findings |
| --- | ---: | ---: | ---: | ---: | ---: |
| `python/` | 12 | 87 | 1 | 86 | 19 |
| `inter_file/python/` | 2 | 4 | 1 | 3 | 1 |
| `java/` | 11 | 35 | 0 | 35 | 20 |
| `inter_file/java/` | 2 | 4 | 1 | 3 | 1 |
| `javascript/` | 6 | 45 | 0 | 45 | 9 |
| `inter_file/javascript/` | 2 | 8 | 1 | 7 | 1 |
| **Total** | **35** | **183** | **4** | **179** | **51** |

Each scan loads only its language's registered analyzer through controlled entry
points. Scanner preparation, routing, indexing, traversal, and analysis remain
real. Regex, dependency, PHP, and Ruby analyzers are excluded; fixture programs
are never executed. The database boundary is mocked to prevent history writes.
User/project rule overlays are excluded for reproducibility, not replaced with
simplified security models. A repeated factory-only run matched every event,
summary, warning/error list, and finding count from the initial run. All six
warning/error lists were empty; no conflict or analysis failure was observed.

The six roots follow existing language/inter-file test project boundaries.
Scanning the entire corpus as one project is a different experiment: unrelated
fixture declarations could collide and Python module roots would change. These
results must not be extrapolated to arbitrary project-root choices or real-world
application populations. Inline/generated fixtures in test modules are not
included in these totals; existing tests are supplementary evidence only.

Reproduce from the repository root with the project's installed dependencies:

```bash
PYTHONPATH=. python tests/tools/audit_resolution_diagnostics.py > /tmp/resolution-audit.json
```

The investigation-only helper captures each event's language, repository-relative
file, start/end line and column, call name, status, reason, candidate count/identities, and
source line. It also captures Python binding facts and aggregates by
`(language, status, reason, call_name)`. It does not classify calls automatically
or modify production reporting. The complete 183-site snapshot, retaining the original manual classifications,
is [resolution-diagnostics-denominator-events.tsv](resolution-diagnostics-denominator-events.tsv).
Its A/B/C annotations are fixture-specific observations, not an API allowlist.

Runtime: Tree-sitter 0.23.2, Java grammar 0.23.5, JavaScript grammar 0.23.1,
PyYAML 6.0.3. Factory KB SHA-256:
`cd5348f7f147d387a0bcc4531dd738c837caba9805a167342a455bd932cc6a01`.

## Observed distributions

| Language | Total | Resolved | Unresolved | Ambiguous | Unsupported | Candidates > 0 | Candidates = 0 |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| Python | 91 | 2 | 89 | 0 | 0 | 2 | 89 |
| Java | 39 | 1 | 38 | 0 | 0 | 1 | 38 |
| JavaScript | 53 | 1 | 52 | 0 | 0 | 1 | 52 |

Reasons are exactly `NONE` for the four resolved sites and `NO_CANDIDATES` for
all 179 unresolved sites. `MULTIPLE_CANDIDATES`, `EXPLICIT_TARGET_NOT_FOUND`,
`UNSUPPORTED_BINDING`, and `UNSUPPORTED_CALL_FORM` do not occur in these trees.
Their absence is a corpus limitation, not evidence that these outcomes are
unimportant. Existing Phase 2 tests exercise them through controlled real scans.

Common names (counts are sites, never raw traversal attempts):

| Language | Call names and counts |
| --- | --- |
| Python | `app.route` 12; `request.args.get` 11; `Flask` 6; `os.system` 5; `sqlite3.connect`, `cursor.execute`, `str` 4 each; `HttpResponse` 3; `print` 2; `logging.info` 1 |
| Java | `executeQuery` 9; `getParameter` 7; `createStatement` 4; `getInstance` 3; `readObject`, `getResultList`, `println` 2 each; `prepareStatement`, `setString`, `runQuery` 1 each |
| JavaScript | `require` 12; `res.send` 8; `express`, `app.get` 6 each; empty name 7; `console.log` 3; `crypto.createHash`, `app.post` 2 each; `runCommand`, `cp.exec` 1 each |

Every name/status/reason combination is reproducible in the helper's JSON
`aggregates`; the table intentionally shows the common/architecturally relevant
subset rather than dumping logs.

## Clearly project calls

Manual fixture evidence and evidence currently available to the resolver differ:

| Language | A: fixture-evidenced project sites | With indexed candidates | Additional manual project evidence |
| --- | ---: | ---: | --- |
| Python | 3 | 2 | Local class constructor `User()` 1 |
| Java | 1 | 1 | None |
| JavaScript | 1 | 1 | None |

Four sites have machine-observable indexed evidence:

- Python `inter_file/inter_file_app.py:9` calls `vulnerable_execute`, explicitly
  imported from the indexed project module `inter_file_utils`. One candidate,
  resolved. This is the sole supported explicit project binding in these events.
- Python `final_kb_tests.py:7` calls `send_email`, with one candidate declared
  later in the **same file** at line 15. It reaches project lookup because the
  visitor has not registered that local declaration yet. Project lookup therefore
  does not imply inter-file lookup; source order affects local bypass behavior.
- Java `inter_file/Controller.java:13` calls `helper.runQuery`; the event name is
  bare `runQuery`, with one candidate in `DatabaseHelper.java`, resolved.
- JavaScript `inter_file/app.js:10` calls bare `runCommand`, with one candidate in
  `db.js`, resolved. The fixture has a CommonJS import, but the resolver uses only
  the existing global name lookup; this is not module-binding support.

Python `field_sensitivity_test.py:13` calls `User()`, where the class is declared
at line 6 in that file. This is demonstrably project code by manual inspection,
but has zero candidates because Python indexes top-level functions, not class
constructors. It is unresolved/`NO_CANDIDATES`. This fifth A site is not detectable
by the proposed “explicit binding or indexed candidate” filter today.

Paths in these examples abbreviate `tests/test_code/<language>/` or
`tests/test_code/inter_file/<language>/`; the snapshot contains complete paths.

## Clearly non-project calls

Group B means strong evidence in these fixtures: imported APIs, established
receiver construction/types, framework callback context, or unshadowed builtin
usage. It does not mean the engine currently proves external ownership.

| Language | B sites | Representative evidence |
| --- | ---: | --- |
| Python | 84 | Flask/FastAPI imports and app construction; sqlite3 connections/cursors; os/hashlib/Crypto/jwt/logging imports; builtin printing/conversion |
| Java | 38 | Servlet/SQL receiver types and fixture intent; standard crypto/deserialization/logging APIs; `System.out.println` |
| JavaScript | 52 | `require` declarations and receiver origins (Express/axios/jwt/ejs/crypto); callback response APIs; console/Math/eval builtins |
| **Total** | **174** | All unresolved/`NO_CANDIDATES`, zero candidates |

Specific questions:

- **Python printing:** `print` generates two diagnostics (`new_rules_test.py:26`
  and `inter_file_utils.py:10`), despite being a PII sink in a matching category.
  Four `str` calls also generate diagnostics. No fixture shadows these builtins.
- **Python command sink:** all five `os.system` sites generate diagnostics:
  `complex_vulnerable_app.py:34,37`, `vulnerable.py:16,25`, and
  `inter_file_utils.py:6`. The command-injection visitor handles these as sinks,
  while other active detector visitors probe the project index.
- **Python sources:** all eleven `request.args.get` sites, one `request.GET.get`,
  and one `request.headers.get` site generate diagnostics. Assignment source
  detection does not suppress subsequent `visit_Call` traversal. Non-call source
  accesses such as `request.GET['id']` or `request.POST` are not calls and do not
  generate their own resolution events.
- **Python sanitizers:** no executable known sanitizer call occurs in the audited
  Python trees. The comment “or sanitized” in `safe_execute` is not a sanitizer
  implementation. Zero observed sanitizer sites must not be interpreted as
  successful exclusion. Existing Phase 2 characterization tests separately
  demonstrate sanitizer calls reaching lookup.
- **Java printing/sources:** two `println` sites and seven `getParameter` sites
  become attempts. Java stores bare names even when the source is qualified.
  Nine `executeQuery` sites also appear despite SQL-sink handling in its category.
- **Java sanitizer:** `Safe.java:8` calls `prepareStatement`, a configured SQL
  sanitizer, and produces one unresolved diagnostic. `setString` at line 9 also
  produces one, but is **not** in the configured sanitizer list; do not conflate
  parameterized SQL fixture intent with this specific KB model.
- **Java framework exclusions:** `getWriter` and both `createQuery` call sites in
  `LegacyAndHibernate.java` produce no events: the framework mapper handles them
  independently of detector-specific KB sinks. The outer `write` and two
  `getResultList` calls still generate events. Local `runHibernateQuery` is
  registered before its call and creates no project-resolution diagnostic.
- **JavaScript logging/sinks:** three `console.log` sites, eight `res.send`, one
  `cp.exec`, and one `eval` site generate events. Sink recognition in a matching
  category does not prevent lookup in another category. Source accesses
  `req.query`, `req.body`, and their properties are not call expressions and
  generate no own events. No known sanitizer call occurs in these JS trees.
- **JavaScript loaders:** twelve `require` sites are builtin loader calls,
  including `require('./db')`. Loading a project module does not make the loader
  itself an indexed project function; it is classified B, not A.

Known sinks are excluded **per matching visitor**, not reliably from the union
of diagnostics produced by a full scan. The fixture tests protect this difference
and the unconditional Java framework exclusion; no exclusion behavior is changed.

## Unknown calls

Four sites are classified C, all Python, unresolved/`NO_CANDIDATES`:

| Location | Call | Why classification is unsafe |
| --- | --- | --- |
| `crypto_tests.py:6,16` | `data.encode` (2 sites) | `data` is an untyped parameter. String encoding is plausible, but a project-defined object could provide `encode`. No candidate does not establish builtin ownership. |
| `mass_assignment.py:12` | `User.objects.get` | Relative `.models` import has no supplied models file; receiver/manager identity is not available. The fixture suggests Django ORM use, but a custom project manager is possible. |
| `mass_assignment.py:14` | `user.save` | The receiver comes from that unresolved model/manager. Framework and project override dispatch cannot be distinguished. |

Java and JavaScript have zero C sites **after manual review of these particular
fixtures**. Bare Java names and unnamed JS calls would often be unclassifiable
from event payloads alone. Imports, receiver construction, declared types, and
source context were used for this manual audit; no general classifier is implied.
The known local `User()` constructor is A by fixture evidence, despite looking
like any other zero-candidate failure to the current resolver.

Classification reconciliation: Python A/B/C = 3/84/4; Java = 1/38/0;
JavaScript = 1/52/0. Total = 5/174/4 = 183. The original B total was 171;
only identity splitting adds three B rows, with no classification changes.

## Noise sources

1. **Fallback probes dominate:** 179/183 sites have zero candidates. Manual
   review identifies 174 clearly non-project probes, one unindexed project
   constructor, and four unsafe-to-classify sites among them. Removing all
   zero-candidate observations would remove meaningful project limitations too.
2. **Detector-dependent bypass:** known sinks/sources/sanitizers are not a global
   exclusion set. The denominator depends on the active security categories,
   not just how many project functions exist. It must not be advertised as
   application understanding or security-analysis coverage.
3. **Dotted JavaScript semantics:** 26/52 unresolved sites have nonempty dotted
   names and use exact lookup. All 26 are B in these fixtures. Another seven
   identities have empty names from chained call receivers, leaving 19 unresolved
   bare-name sites (`require` 12, `express` 6, `eval` 1). Exact dotted-name failures
   are substantial noise here, but zero candidates cannot prove future dotted
   calls are external: project object/module members can also be unsupported.
4. **Previously collapsed JavaScript identities (corrected):** the crypto and
   Math chains shared start points and empty names. Seven unnamed syntactic calls
   originally collapsed to four identities; complete source spans now preserve
   all seven. The corrected regression checks complete Tree-sitter call spans.
   Call-name extraction is unchanged and can still be empty; that is a separate
   representational limitation, not a reason to collapse different spans.
5. **Index/local limitations:** Python's forward `send_email` declaration is
   counted through project lookup while already registered locals bypass it;
   the known `User` class is absent from the function index. Neither presence
   nor absence of a diagnostic alone identifies project understanding.

## Resolution provenance

A structured attempt-origin/evidence dimension would materially improve honesty.
`UNRESOLVED/NO_CANDIDATES` currently groups an unindexed project constructor,
obvious library calls, and unknown receivers. `ResolutionStatus` should continue
answering what decision was made. Provenance should separately answer which
existing facts justified entering the project-resolution path.

Distinguish conceptually:

- An explicit binding to a **known project module**, including a target
  symbol absent from that module. A syntactic import alone is insufficient:
  `os`, Flask, and third-party imports do not establish project ownership.
- Candidate-backed lookup under the existing language semantics. This is evidence
  of a project candidate, not proof of receiver binding or exact semantic target.
- An unconstrained fallback probe, including zero-candidate/unknown-name probes.

`EXPLICIT_PROJECT_BINDING`, `INDEX_CANDIDATE`, and `GLOBAL_FALLBACK` are design
examples only. Candidate presence is already available in the payload, so an
exclusive enum might mix *attempt trigger* with *evidence discovered by the
attempt*. Prefer discussing a stable origin plus existing candidate evidence,
or clearly documenting precedence/overlap, before choosing a schema.
Classification should be derived from facts already used in resolution; it must
not add a second lookup or change candidate selection. Unsupported known bindings
need care: a known unsupported alias can refer to an external module, so it must
not automatically become “explicit project target.”

The corpus would yield one explicit-project-bound site and three other
candidate-backed sites. Provenance still cannot automatically recover the local
class constructor's intent or classify the four unknown receivers without
additional frontend facts. It is useful separation, not a universal ownership
resolver. Stable origin fields must also remain deterministic across detector
and recursive revisits; do not encode traversal-dependent “last trigger wins.”

## Metric options

| Option | Observed effect | Benefits | Costs/limitations |
| --- | --- | --- | --- |
| A: all resolver-site identities | 183 sites, 4 resolved | Honest account of actual probes; preserves unknown and unsupported attempts; no loss of observations | Includes 174 clearly non-project sites here; category/local/name extraction affects counts. Useful diagnostic workload, misleading project-understanding metric. |
| B: explicit project binding or candidate present | 4 sites here, all resolved (Python 2, Java 1, JS 1) | Far less fallback noise; defensible project-evidence denominator | Drops the known local `User()` constructor and four unknown sites here. Misses unsupported project members/classes/import forms when evidence is not represented. Retaining explicit project binding is essential for meaningful zero-candidate failures. |
| C: all events plus structured origin/evidence | Retains all 183; permits separately labeled candidate/binding and fallback subsets | Preserves maximum information; exposes resolution decision separately from reason for attempting it; no external API blacklist needed | Requires a schema/design discussion, frontend fact definitions, deterministic duplicate policy, and tests. Provenance does not repair missing semantics or incomplete call-name representation. |

The static corpus contains no explicit missing-import target. Nevertheless, the
existing `test_python_import_events_copy_decision` case in
`tests/test_resolution_diagnostics.py` scans an existing project module lacking
its imported function and records `UNRESOLVED/EXPLICIT_TARGET_NOT_FOUND` with zero
candidates. A candidates-only filter would discard this meaningful failure.
Option B must preserve explicit binding evidence, not merely `candidate_count > 0`.
Do not claim B solves unsupported relative imports or classes: current module and
index facts cannot always establish that evidence.

## Recommendation

Choose Option C as the direction for the **next design discussion**, retaining
all observations. Before ScanResult/UI exposure:

1. Define attempt origin independently of resolution status, using existing
   project binding and candidate facts. Keep fallback probes and unknowns visible.
2. Specify user metrics as separately labeled resolver-probe counts,
   project-evidenced lookup outcomes, and fallback outcomes. Publish denominator
   definitions and limitations; none is “percentage of application understood.”
3. Source-span identity now separates the observed chained calls. Keep tests for
   complete spans and genuinely unavailable-position fallbacks; do not assume
   provenance alone supplies missing source-location or call-name information.
4. Validate meaningful zero-candidate explicit targets, unsupported bindings,
   category-dependent revisits, and recursion against the existing invariants.
   Add further corpora before making general population claims.

Do not introduce a growing `print`/`println`/`console.log` blacklist. Existing
security semantics can be discussed separately where they justify bypass, with
finding compatibility tests, but reclassifying calls is not necessary to retain
honest observability. Structured provenance and user metrics remain unimplemented. The only subsequent
implementation reported here corrects source-span identity.
