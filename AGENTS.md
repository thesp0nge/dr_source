# DRSource Agent Guidelines

## Purpose

DRSource is an open-source Static Application Security Testing (SAST) engine focused on understanding code well enough to produce precise, explainable, and actionable security findings.

The project is not intended to clone another SAST product or follow another project's architecture or feature roadmap.

Semgrep may be used as a reference for the level of engineering quality, usability, precision, testing, and maturity we want to achieve, but DRSource must maintain its own architecture and product identity.

The long-term direction is:

> deterministic static analysis at the core, with optional AI-assisted reasoning built on top of deterministic analysis results.

The deterministic core must remain useful, testable, reproducible, and fully functional without AI.

---

## Engineering priorities

When making changes, optimize for these properties, in this order:

1. Correctness
2. Precision and false-positive control
3. Explainability
4. Determinism and reproducibility
5. Maintainability
6. Performance and bounded resource usage
7. Developer experience
8. Feature breadth

Do not trade correctness for feature count.

Do not add support for more languages or vulnerability categories when doing so would weaken existing analysis guarantees.

---

## Current architecture

The repository is broadly divided into:

* `dr_source/core/`

  * scan orchestration
  * project indexing
  * knowledge-base loading
  * persistence and common utilities

* `dr_source/plugins/`

  * language-specific analyzers
  * regex analysis
  * structural/pattern analysis
  * dependency analysis

* `dr_source/config/knowledge_base.yaml`

  * security knowledge
  * vulnerability metadata
  * sources
  * sinks
  * sanitizers
  * regex and structural patterns

* `dr_source/reports/`

  * reporting and export formats such as SARIF

* `tests/`

  * unit tests
  * integration tests
  * analysis fixtures and vulnerable/safe sample programs

Keep these responsibilities separated.

Do not move security knowledge into language visitors when the same information belongs in the knowledge base.

Do not move language-specific AST semantics into the generic core unless there is a clear language-independent abstraction.

---

## Core architectural principles

### Deterministic analysis first

Security findings produced by the core analysis engine must be deterministic for the same:

* source tree
* DRSource version
* ruleset
* configuration

AI or probabilistic models must never be required to determine basic static-analysis facts such as whether a known source reaches a known sink.

### Parse facts, then reason about them

The desired architectural direction is:

```text
source code
    ↓
language frontend / parser
    ↓
symbols + semantic facts
    ↓
data-flow / security facts
    ↓
findings
    ↓
reporting / optional AI reasoning
```

Avoid increasing long-term dependence on repeated ad-hoc AST traversals inside individual vulnerability detectors.

### Language frontends may differ

Do not attempt to force every language into an identical AST representation.

Python may use the native Python AST.

Java, JavaScript, PHP, Ruby, and other languages may use Tree-sitter or other appropriate parsers.

Shared analysis semantics should eventually live above those parser-specific representations.

### Security knowledge and analysis mechanics are different concerns

Examples of security knowledge:

* `request.args.get` is a possible source
* `os.system` may be a command-execution sink
* a specific API can sanitize a specific class of data

Examples of analysis mechanics:

* assignment propagation
* scope handling
* symbol resolution
* alias tracking
* interprocedural propagation
* field sensitivity

Do not mix these unnecessarily.

---

## Project indexing and inter-file analysis

Cross-file analysis is a core capability.

Changes to project indexing, symbol resolution, call resolution, or interprocedural analysis must be treated as high-risk changes.

Never assume that a function name alone uniquely identifies a symbol.

When evolving the project index, account for concepts such as:

* language
* file/module/package
* owning class or object
* symbol name
* arity or signature where relevant

Do not introduce additional name-based heuristics that silently overwrite symbols from unrelated scopes.

Any change to cross-file behavior must include integration tests.

---

## Taint-analysis semantics

Treat these as conceptually different properties:

```text
trust:
    trusted
    untrusted

sensitivity:
    normal
    pii
    credential
    secret
```

Do not automatically treat sensitive data and untrusted data as semantically identical.

A sanitizer must not be considered globally valid merely because its function name appears in a sanitizer list.

Sanitization is context dependent.

For example:

* HTML encoding is not SQL sanitization
* SQL escaping is not shell escaping
* URL encoding is not HTML encoding

When modifying sanitizer semantics, add both positive and negative regression cases.

---

## Knowledge-base changes

`dr_source/config/knowledge_base.yaml` is part of the analysis engine's public security behavior.

Changes to the knowledge base require the same review discipline as code changes.

Every new or modified rule should have tests demonstrating:

* vulnerable code that must be detected
* safe code that must not be detected

Do not claim support for a vulnerability or framework based on a single positive example.

Prefer precise source/sink/sanitizer models over long lists of loosely matched function names.

Avoid implicit substring matching when exact, suffix, qualified-symbol, or explicitly declared wildcard semantics can be used.

Do not add compatibility syntax for another tool unless it provides clear value to DRSource independently.

---

## Findings

Security severity and detection confidence are different concepts.

Do not conflate them.

A vulnerability can have high security impact but only medium analysis confidence.

The long-term finding model should be capable of representing:

* rule identity
* vulnerability category
* CWE
* severity
* confidence
* primary location
* source
* sink
* code/data-flow evidence
* engine or analyzer identity
* stable fingerprint
* metadata

Avoid adding new output formats that depend directly on ad-hoc strings when structured finding data can be used instead.

---

## Bug-fix workflow

When fixing a suspected bug:

1. Understand the current behavior.
2. Reproduce the bug with the smallest useful regression test.
3. Confirm that the new regression test fails for the expected reason.
4. Make the smallest production-code change that fixes the underlying problem.
5. Confirm that the regression test passes.
6. Run the complete test suite.
7. Check for unintended changes in findings or behavior.

Do not modify production code merely because an assumption says the behavior is wrong.

Do not make unrelated cleanup changes in the same bug-fix patch.

A passing existing test suite does not prove that a suspected bug does not exist. Add a test covering the precise behavior under investigation.

---

## Tests

The full test suite is the minimum acceptance gate.

Run:

```bash
pytest -q
```

For focused work, run the relevant test module first, then the complete suite before considering the task complete.

Tests should make precise assertions whenever practical.

Prefer:

```python
assert finding.rule_id == "SQL_INJECTION"
assert finding.line_number == 42
```

over:

```python
assert len(findings) > 0
```

For security rules, prefer paired fixtures:

```text
positive/
negative/
```

or equivalent explicit vulnerable/safe cases.

Tests must not write persistent scan databases into a developer's normal DRSource history.

Tests involving external tools or services must be deterministic and isolated through mocks or controlled fixtures unless explicitly designated as integration/network tests.

Do not weaken an assertion solely to make a test pass.

---

## Test fixtures

Files under `tests/test_code/` may intentionally contain:

* vulnerable source code
* unsafe APIs
* fake secrets
* filenames that resemble test modules

Treat them as analysis inputs, not necessarily Python test files.

Do not "fix" deliberately vulnerable fixture code unless the test scenario itself is being changed.

---

## Plugin contract

Analyzer plugins must respect the common DRSource plugin contract.

Plugins should:

* declare their supported inputs explicitly
* return structured findings
* fail gracefully on malformed or unsupported input
* avoid terminating the whole scan because one file cannot be analyzed
* avoid hidden global state
* avoid writing persistent state directly unless explicitly part of the plugin's responsibility

Do not introduce new optional behavior through `hasattr()` or undocumented attributes when the behavior belongs in an explicit interface or capability.

If the plugin contract needs to change, treat that as an architectural change rather than a local implementation detail.

---

## Error handling

Do not silently swallow unexpected exceptions.

Avoid constructs such as:

```python
except:
    pass
```

unless there is a documented and justified reason.

Parsing failures, unsupported constructs, timeouts, plugin failures, and internal analysis failures should be distinguishable where possible.

A scan completing successfully while silently skipping significant analysis is a correctness problem.

Prefer diagnostics over silent degradation.

---

## Performance

Avoid algorithms whose cost unnecessarily scales as:

```text
files × rules × complete AST traversal
```

when the same semantic facts could be extracted once and reused.

Prefer:

```text
parse once
extract facts once
evaluate multiple security models
```

when evolving the architecture.

Do not optimize by reducing analysis correctness without an explicit design decision.

Any substantial performance optimization should include evidence that security behavior has not changed unexpectedly.

---

## Timeouts and resource safety

Static analysis processes attacker-controlled or otherwise untrusted source trees.

Treat input files, syntax trees, regular expressions, dependency manifests, and rule files as untrusted input.

Analysis should eventually have bounded:

* execution time
* recursion depth
* memory consumption
* file size handling
* traversal depth where applicable

Avoid introducing regexes or recursive algorithms that can cause uncontrolled resource consumption.

---

## Reporting and SARIF

Reporting code should consume structured analysis results.

Do not encode analysis semantics only inside reporter-specific strings.

SARIF should eventually preserve:

* correct severity mapping
* rule metadata
* CWE information
* stable fingerprints
* source/sink traces
* code flows where appropriate

Changes to reporting must not change the underlying finding semantics.

---

## AI features

AI is an optional reasoning layer, not a replacement for deterministic static analysis.

Good uses of AI include:

* explaining deterministic findings
* helping triage findings
* contextual code review
* suggesting framework models
* proposing rules
* proposing remediation
* summarizing security evidence

AI must not silently decide or rewrite trusted deterministic analysis facts.

AI-generated rules or security models must not become trusted automatically.

They require deterministic validation and tests.

AI-generated remediation must be validated by re-analysis and, where available, project tests.

Remote AI use must be explicitly enabled.

Do not send source code, credentials, secrets, findings, or repository content to remote AI providers by default.

Repository contents must be treated as untrusted prompt input. Source-code comments, README files, strings, or other repository text must never be allowed to override system-level AI instructions.

---

## Scope discipline for coding agents

When assigned a task:

* modify only the files required by the task
* avoid opportunistic refactoring
* do not rename public concepts without need
* do not change public behavior unless the task requires it
* do not introduce new dependencies without justification
* do not change the knowledge-base schema without explicit approval
* do not add new languages while fixing unrelated behavior
* do not add AI functionality while working on deterministic-core stabilization
* do not rewrite working components merely to make them "cleaner"

If a deeper architectural problem is discovered during a scoped task, report it separately instead of silently expanding the patch.

---

## Architectural changes

The following require explicit design discussion before implementation:

* changing the plugin API
* changing the finding model
* changing the knowledge-base schema
* replacing or substantially redesigning `ProjectIndex`
* introducing a new intermediate representation
* changing interprocedural-analysis semantics
* introducing concurrency or multiprocessing
* adding remote services
* adding AI providers
* changing persistence formats
* adding a new language frontend

For these changes, prefer a short design note or ADR before implementation.

---

## Definition of done

A task is complete only when:

* the requested behavior is implemented
* regression tests exist where appropriate
* relevant focused tests pass
* the full test suite passes
* no unrelated behavior was intentionally changed
* new failure modes are handled explicitly
* documentation is updated when public behavior changes
* the change does not silently reduce security coverage
* the final diff has been reviewed for unnecessary changes

For bug fixes, explicitly report:

```text
Root cause
Regression test
Fix
Tests executed
Remaining limitations
```

For architectural work, also report:

```text
Design trade-offs
Compatibility impact
Migration impact
Follow-up work
```

---

## Local development

DRSource supports Python 3.9 and later unless the project metadata is explicitly changed.

Typical setup:

```bash
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
pytest -q
```

Before making changes, confirm the working tree and baseline:

```bash
git status
git rev-parse HEAD
pytest -q
```

Do not assume failures already existed. Record the baseline when beginning substantial work.

---

## Agent reporting

After completing a task, provide a concise engineering summary containing:

```text
Files changed:
- ...

Behavior changed:
- ...

Tests added/changed:
- ...

Commands run:
- ...

Result:
- ...

Potential follow-ups:
- ...
```

Do not claim tests passed unless they were actually executed.

Do not claim a vulnerability class is supported unless the implementation and tests justify that statement.

---

## Guiding principle

The primary question for every change is not:

> "Does this add another feature?"

It is:

> "Does this improve DRSource's ability to understand software and turn that understanding into precise, explainable, trustworthy security findings?"

