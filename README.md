# DRSource

DRSource is a professional, extensible, multi-language **Static Application Security Testing (SAST)** tool. It combines high-speed regex pattern matching with advanced **AST-based Inter-File Taint Analysis** and a **Semgrep-compatible Boolean Engine** to identify complex vulnerabilities across entire codebases.

DRSource doesn't just look for "bad strings"; it understands the data flow of your application, tracking user input from entry points (Sources) through logic layers, respecting sanitization functions (Sanitizers), until it reaches dangerous execution points (Sinks).

## Key Features

- **Advanced Inter-File Taint Analysis**: Tracks data flow across different files and modules. It can follow a tainted variable from a web controller in one file to a database helper in another.
- **Semgrep-Compatible Boolean Engine (v0.110.0)**: Supports complex rule definitions using:
  - `patterns`: Logical AND across multiple patterns.
  - `pattern-either`: Logical OR for alternative matching.
  - `pattern-not`: Logical NOT to exclude specific cases (e.g., test code or known safe patterns).
  - **Metavariable Unification**: Real `$X` metavariable matching that ensures multiple occurrences of the same variable name refer to the same AST node.
- **Industrial-Grade Precision**:
  - **Field-Sensitive Taint Tracking**: Differentiates between fields in an object (e.g., flagging `user.name` but ignoring `user.id`), reducing noise in ORM/DTO-heavy modern code.
  - **Constant Propagation**: Automatically identifies and tracks hardcoded values and safe string concatenations, drastically reducing false positives by ignoring safe "sinks".
  - **Scope Management**: Understands local and global scopes, preventing variable name collisions between functions.
  - **AST Sanitizers**: Recognizes security controls (e.g., `escape()`, `prepareStatement`, `int()`).
- **Multi-Engine Analysis**:
  - **Tree-sitter Powered**: Uses industrial-grade parsers for Java and JavaScript/TypeScript for robust analysis of modern syntax.
  - **Native Python AST**: Deep integration with Python's native AST for precise data-flow tracking.
- **Professional Knowledge Base**: Highly configurable YAML-based rules engine with support for configuration overlays (Default, User, Project, CLI).

## Supported Languages & Frameworks

- **Java**: Spring, Servlets, JDBC.
- **Python**: Flask, Django, FastAPI, standard library.
- **JavaScript/TypeScript**: Node.js (Express), Sequelize, Prisma, Axios, Browser-side JS.

## Boolean Rule Example

DRSource allows defining sophisticated logic directly in YAML:

```yaml
SELF_COMPARISON:
  description: "Comparing a variable to itself is usually a bug."
  severity: "LOW"
  language_specific:
    python:
      patterns:
        - pattern: "$X == $X"
        - pattern-not: "1 == 1"
```

## Installation

Clone the repository and install in editable mode:

```sh
git clone https://github.com/thesp0nge/dr_source.git
cd dr_source
pip install --editable .
```

## Usage

```sh
# Standard scan of a directory
dr_source /path/to/codebase

# View full data-flow traces
dr_source --show-trace /path/to/codebase

# Export to SARIF for CI/CD integration
dr_source --export sarif --output report.sarif /path/to/codebase
```

## Library API

```python
from dr_source.core.scanner import Scanner

result = Scanner("path/to/project").scan()
for finding in result.findings:
    print(finding.vulnerability_type, finding.file_path, finding.line_number)

print(result.metrics.files_selected)
```

`ScanResult` and `ScanMetrics` are available from `dr_source.core.result`.
Result containers are immutable; findings and their traces are defensive copies
of Scanner state, but individual `Vulnerability` values remain mutable.
`files_selected` counts selected files, including work later skipped or failed.
Scanner still writes scan history to SQLite; persistence extraction is deferred.

`result.diagnostics`, `result.resolution_summary`, and
`result.resolution_origin_summary` describe recorded project-resolution attempts,
including explicit project bindings, candidate-backed lookups, and fallback
probes. They do **not** measure total application-call coverage; fallback probes
do not imply external-library ownership.

ASCII and SARIF reporters accept structured finding sequences:

```python
from dr_source.reports.ascii import ASCIIReport
from dr_source.reports.sarif import SARIFReport

print(ASCIIReport().generate(result.findings))
sarif = SARIFReport().generate(result.findings)
```

In 0.172.0 these reporter APIs replace dictionary inputs. JSON exports retain
their existing compatibility schema. See [ScanResult design](docs/adr/0004-scan-result.md)
and the [pre-1.0 versioning policy](docs/versioning.md) for API expectations.

## License

DRSource is licensed under the MIT License.
