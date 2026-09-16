# Python import resolution: Phase 3 investigation

Status: Characterization and proposed minimum scope; no production changes.

This note complements [ADR 0001](adr/0001-project-index-symbol-identity.md).
The tests in `tests/test_python_import_resolution.py` assert current behavior;
their missing findings are known analysis gaps, not evidence of safe code.
There are no skipped tests or expected-failure markers.

## Facts established by the current implementation

- `Scanner.__init__` retains `target_path` but constructs `ProjectIndex()` without
  passing it a scan root, project root, or source/import root. Directory scans
  collect descendants; single-file scans collect only the target file.
- `ProjectIndex` stores language, supplied file path, declaration position, and
  name. IDs normalize paths lexically, but do not make them absolute or relative
  to a known root. Owner/signature remain unknown; no Python module field exists.
- `PythonAstAnalyzer.index` parses a complete file but registers only top-level
  synchronous/asynchronous function nodes. It does not retain the enclosing
  module AST or an import-binding table as part of the definition.
- `PythonAstAnalyzer.analyze` knows its file path, but does not pass it to
  `PythonTaintVisitor`. The visitor has source/sink models, local function and
  taint dictionaries, the shared project index, and a recursion depth; it has no
  current-file, module, package, or import-root context.
- There are no Python resolver handlers for `Import` or `ImportFrom`. These AST
  nodes are traversed generically without recording import bindings. Parsing with
  `filename=file_path` during indexing does not attach module identity to a
  function node.
- Global lookup supplies the syntactic call name and `language="python"`, after
  sink handling and a local function-dictionary check. Candidate lookup is exact
  by name, not by imported module. A singleton remains a compatibility heuristic.

## Call forms: keep the information layers separate

| Source form | Syntax / `_get_full_call_name()` | Import binding needed | Module identity needed | Candidate lookup needed |
| --- | --- | --- | --- | --- |
| `from service_a import execute; execute(value)` | `Name("execute")` / `execute` | Local `execute` binds to member `execute` of module `service_a`. | Match `service_a` to an indexed source unit under a known Python import root. | Python `execute` candidates restricted to that source unit. |
| `import service_a; service_a.execute(value)` | `Attribute(Name("service_a"), "execute")` / `service_a.execute` | Local `service_a` is an imported module, not an arbitrary object. | Same module-to-file mapping. | Lookup member `execute` within the bound module, not the literal dotted string. |
| `from service_a import execute as run; run(value)` | `Name("run")` / `run` | Local `run` binds to the original module/member pair. | Same mapping; the alias is not a new module or declaration. | Lookup original `execute`, not global `run`. |
| `import service_a as svc; svc.execute(value)` | `Attribute(Name("svc"), "execute")` / `svc.execute` | Local `svc` binds to module `service_a`. | Same mapping; never infer a module named `svc`. | Lookup original member in the bound module. |

Today the from-import case returns both Python `execute` definitions, logs
ambiguity, and skips simulation. The qualified and alias cases return no
candidates for their literal names and produce no ambiguity warning. None finds
the valid source-to-sink path in the test project.

An unrelated globally indexed function named `run` could currently satisfy a
`run(...)` lookup regardless of its import alias. That follows from the name-only
lookup mechanism; the alias fixture deliberately contains no such definition.
Aliases need binding records, not string substitution against all global names.
The syntactic `asname` is available, but correct shadowing/rebinding and scope
rules are additional work. Alias support is deferred.

## Recursive/inter-file context

When a unique global function is found, `_simulate_call` receives `g.file_path`
as `t_file`. It uses only the basename for the trace step identifying the callee.
It then constructs another `PythonTaintVisitor` with analysis models, the shared
index, and increased depth; it seeds tainted parameters and visits the callee's
function AST. It does not pass `t_file`, the caller file, the callee module AST,
or either file's imports to the child visitor.

Consequently module-level imports in a callee cannot be recovered by merely
walking its function body. Future simulation must select the callee's own file
and binding context, not reuse the caller's imports. Current findings are wrapped
by the outer analyzer using its analyzed file path; the trace's callee basename
is not a complete file-context model. This task changes neither reporting nor
recursive analysis.

## Current tests versus desired future behavior

All new fixtures live in `tmp_path` and use the real Scanner, ProjectIndex,
Python indexer, knowledge base, and taint visitor. Only plugin discovery is
restricted to the Python analyzer. Existing test database isolation is retained.

| Scenario | Passing characterization assertion now | Desired Phase 3 assertion |
| --- | --- | --- |
| Two `execute` definitions, `from service_a import execute` | Both definitions are indexed; no finding; diagnostic lists both Python candidates. | Select only `service_a.execute` and report its command-injection flow. |
| Same definitions, `import service_a; service_a.execute(value)` | Call name is `service_a.execute`; no exact-name candidate or finding. | Follow the module binding to `service_a.execute` and report the same flow. |
| From-import alias `run` | Call name is `run`; no candidate or finding. | Deferred alias-specific work. |
| Module alias `svc.execute` | Call name is `svc.execute`; no candidate or finding. | Deferred alias-specific work. |
| Unique `execute`, with and without a from-import | One command-injection finding with the exact source and cross-file trace in both cases. | Preserve the successful supported flow; do not mistake the no-import control for valid runtime Python binding. |

The unique-symbol controls establish that the sink and taint source work. Missing
findings in the two-module cases therefore characterize resolution limitations;
the tests also reject analyzer errors as an explanation. Future implementation
should replace the relevant current-behavior assertions, not leave contradictory
absence assertions beside success tests.

Before declaring Phase 3 support, add paired future negative cases importing
the safe `service_b.execute` while the vulnerable `service_a.execute` remains
indexed. They must produce no flow into service_a. Candidate and diagnostic
results must remain independent of file registration order. No desired-future
success test is installed as a permanently failing or skipped test here.

## Smallest reliable Python module mapping

Mapping requires a declared Python source/import root, which may differ from a
repository root or scan target. For a conventional source tree rooted at `R`:

| Indexed source path | Python module identity |
| --- | --- |
| `R/service_a.py` | `service_a` |
| `R/pkg/service_a.py` | `pkg.service_a` |
| `R/pkg/__init__.py` | `pkg` |

Normalize the root and file to the same absolute path basis for containment and
relative-path calculation. Derive identity from the path relative to `R`, remove
the `.py` suffix, and join directory/name components with dots. An `__init__.py`
represents its containing package, not `pkg.__init__`. Preserve case. Require
valid module components and, for the initial regular-package model, explicit
`__init__.py` package boundaries. Missing boundaries are unsupported rather than
assumed namespace packages. Do not execute imports or consult ambient `sys.path`.

Relative scan targets must be anchored once against the invocation's working
directory. Absolute checkout paths are provenance, not module names. Files
outside the selected root or reachable through uncertain symlink/root aliases
must not get identities from arbitrary basename stripping. Multiple files mapping
to one module, such as `pkg.py` and `pkg/__init__.py`, require an explicit ambiguous
or unsupported result, not a guessed import precedence.

For a `src/` layout, select `R/src` as the import root explicitly rather than
guessing it or treating `src` as a package. Scanning a package directory itself
does not establish that directory's parent as the import root. A root-level
`__init__.py` cannot acquire a reliable package name from the scan directory's
basename alone. Use an explicit enclosing import root or leave the package
identity unknown. Automatic package/root discovery is out of scope.

A single-file scan still indexes only that file. Its parent could be a documented
default root for a standalone module, but cannot establish nested package context
or make sibling dependencies available. Prefer explicit root context for package
files, and leave unindexed imports unresolved. Do not silently expand the scan.

## Where root and module knowledge should live

Root awareness is required somewhere in scan context; it is absent today. The
Scanner is the natural owner of the user-selected target/root policy. A neutral,
read-only root supplied to ProjectIndex is a practical way to expose consistent
context through the existing plugin indexing contract, but the generic index
must not implement Python's path-to-module or import rules.

Compute Python module identities in the Python frontend before registration (or
before associating definitions with Python-specific file metadata), using that
shared root. Keep module-to-file and per-file import-binding facts available to
resolution. ProjectIndex can filter candidates by file without itself computing
Python module names. Thus ProjectIndex root storage is useful plumbing, not a
logical requirement if the frontend is given equivalent explicit context.

## Proposed minimum Phase 3 implementation scope

1. Define one explicit import-root policy; initially support the unambiguous
   directory-root, root-level module cases above. Do not infer source roots from
   basenames or environment state. Specify single-file limitations.
2. Record Python module/file associations and unconditional, unaliased,
   module-level `from service_a import execute` and `import service_a` bindings
   from complete module ASTs. Do not add a general language-neutral module system.
3. Give top-level and recursive visitors current-file context and access to the
   corresponding file's bindings. Switch to the callee context on simulation.
4. For a supported imported bare name or module attribute, translate through the
   binding, identify the indexed source unit, and filter Python symbol candidates
   by original member name and that file. Preserve explicit zero/one/multiple
   outcomes. An explicit but unresolved import must not fall back to an unrelated
   unique global name. Keep existing unbound-name compatibility separately visible.
5. Do not claim a binding when an assignment, parameter, local import, or other
   unsupported shadowing/rebinding could replace it. Conservatively decline those
   cases until modeled; this is a support boundary, not full lexical resolution.
6. Replace the from-import and qualified-call characterization expectations with
   positive/negative binding regressions and preserve the existing inter-file
   suite. Add callee-context and root/path tests before claiming that coverage.

Deferred: import aliases, relative imports, star imports, namespace packages,
dynamic imports, automatic package discovery, re-exports, complex import binding
and execution order, complete shadowing semantics, class/method resolution,
receiver/type inference, call graphs, summaries, and incremental indexing.
