# DRSource

DRSource is a professional, extensible, multi-language **Static Application Security Testing (SAST)** tool. It combines high-speed regex pattern matching with advanced **AST-based Inter-File Taint Analysis** to identify complex vulnerabilities across entire codebases.

DRSource doesn't just look for "bad strings"; it understands the data flow of your application, tracking user input from entry points (Sources) through logic layers, respecting sanitization functions (Sanitizers), until it reaches dangerous execution points (Sinks).

## Key Features

- **Advanced Inter-File Taint Analysis (v0.102.0)**: Tracks data flow across different files and modules. It can follow a tainted variable from a web controller in one file to a database helper in another.
- **Context-Aware Precision**:
  - **Scope Management**: Understands local and global scopes, preventing variable name collisions between functions.
  - **AST Sanitizers**: Recognizes security controls (e.g., `escape()`, `prepareStatement`, `int()`). If data is cleaned, the alert is suppressed, drastically reducing false positives.
  - **Sink Argument Tracking**: Only flags a vulnerability if the tainted data reaches a specific, dangerous argument of a function (e.g., the query string in `db.execute()`, but not the parameters list).
- **Multi-Engine Analysis**:
  - **Tree-sitter Powered**: Uses industrial-grade parsers for Java and JavaScript/TypeScript for robust analysis of modern syntax.
  - **Native Python AST**: Deep integration with Python's native AST for precise data-flow tracking.
  - **Regex Engine**: High-entropy secret scanning (AWS, GitHub, Stripe) and legacy pattern detection.
- **Professional Knowledge Base**: Highly configurable YAML-based rules engine with support for configuration overlays (Default, User, Project, CLI).
- **SARIF Support**: Export results in the standard format for integration with GitHub Security Tab, GitLab, or SonarQube.

## Supported Languages & Frameworks

- **Java**: Spring, Servlets, JDBC.
- **Python**: Flask, Django, standard library.
- **JavaScript/TypeScript**: Node.js (Express), Sequelize, Prisma, Axios, Browser-side JS.

## Knowledge Base Example

DRSource uses a professional schema to define vulnerabilities:

```yaml
SQL_INJECTION:
  description: "Building SQL queries with unvalidated user input."
  severity: "HIGH"
  language_specific:
    javascript:
      ast_sources: ["req.query", "req.body"]
      ast_sinks: 
        - name: "db.query"
          args: [0] # Only the first argument is vulnerable
      ast_sanitizers: ["escape", "validator.escape"]
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

# View full data-flow traces (including inter-file hops)
dr_source --show-trace /path/to/codebase

# Export to SARIF for CI/CD integration
dr_source --export sarif --output report.sarif /path/to/codebase

# Initialize or reset the local scan database
dr_source --init-db /path/to/codebase
```

## Configuration Overlays

Rules are prioritized from highest to lowest:
1. **CLI Override**: `--config /path/to/rules.yaml`
2. **Project Local**: `./.dr_source_rules.yaml`
3. **User Home**: `~/.config/dr_source/knowledge_base.yaml`
4. **Factory Default**: Internal ruleset.

## License

DRSource is licensed under the MIT License.
