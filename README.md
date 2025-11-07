# DRSource

DRSource is an extensible, multi-language static analysis tool designed to
detect vulnerabilities in source code. It uses a pluggable architecture to
combine multiple detection techniques—from simple regex matching to advanced
AST-based taint analysis—all driven by a central, user-configurable knowledge
base.

It identifies security issues such as SQL Injection, Cross-Site Scripting (XSS),
Command Injection, Hardcoded Secrets, and many others across all supported
languages in a single, unified scan.

## Features

- Extensible Plugin Architecture The scanner automatically discovers and runs
  all available analyzer plugins. This allows new languages (e.g., Python, Go)
  and new analysis techniques (e.g., control-flow analysis) to be added without
  changing the corFeatures
- Centralized Knowledge Base All rules—from simple regex patterns to complex AST
  sources and sinks for taint analysis—are defined in a single, human-readable
  knowledge_base.yaml file. This makes it easy to add or customize rules for any
  supported language.

- Multi-Engine Analysis (in one scan) DRSource runs all plugins simultaneously,
  giving you a complete picture of your codebase:

  - Regex Engine: Uses a high-speed, general-purpose regex plugin to find known
    vulnerability patterns and hardcoded secrets in any file type.

  - AST Taint Engine: Performs deep data-flow analysis by parsing code into an
    Abstract Syntax Tree (AST) to track taint from user input sources (e.g.,
    request.getParameter) to sensitive sinks (e.g., executeQuery).

- Persistent Database & Scan Comparison All findings are stored in a local
  SQLite database, allowing you to:

  - View scan history (--history).
  - Compare scans to find new, resolved, and persistent vulnerabilities
    (--compare).

- Robust CLI & Reporting The command-line interface offers powerful options,
  including:
  - Database initialization (--init-db).
  - Exporting results in multiple formats (--export [sarif|json|ascii]).
  - Taint-flow visualization (--show-trace).

## Installation

Clone the repository and navigate to the project root:

```sh
git clone https://github.com/thesp0nge/dr_source.git
cd dr_source
```

Install the package (and all dependencies) in editable mode:

```sh
 pip install --editable .
```

This automatically registers all core plugins (JavaAstAnalyzer, RegexAnalyzer)
so the scanner can find them.

## Usage

Run dr_source against any source code directory. It will automatically detect
all file types and run the appropriate analyzer plugins.

```sh
dr_source [OPTIONS] TARGET_PATH
```

### Options

- TARGET_PATH: The path of the codebase to analyze.
- --init-db: Initialize the database from scratch (drops and recreates tables).
- --history: Display the scan history for the project.
- --compare <ID>: Compare the latest scan with a previous scan specified by ID.
- --export [sarif|json|ascii]: Export scan results in the specified format.
- --output <FILE>: Output file for the exported report.
- --show-trace: Display the full data-flow trace for AST-based vulnerabilities.
- --debug: Enable debug logging.
- --version: Show DRSource version and exit.

## Examples

- Run a Standard Scan This one command runs all plugins (Regex, AST, etc.) on
  the codebase.

```sh
dr_source /path/to/my-project
```

- Export Results as SARIF (Ideal for uploading to GitHub Security)

```sh
dr_source --export sarif --output findings.sarif /path/to/my-project
```

- View Taint Traces

```sh
dr_source --show-trace /path/to/my-project
```

- Initialize the database

```sh
dr_source --init-db /path/to/my-project
```

## Contributing

Contributions are welcome! With the new architecture, there are two main ways to
contribute:

1. Add/Improve a Rule:

- Simply edit the dr_source/config/knowledge_base.yaml file to add a new regex
  pattern or an AST sink/source.

2. Add a New Plugin:

- Create a new plugin package (e.g., dr_source/plugins/python/).
- Write your new analyzer class (e.g., PythonAstAnalyzer) that implements the
  AnalyzerPlugin API.
- Register your new plugin in the entry_points section of setup.py.

For all contributions, please fork the repository, create a new branch, and
submit a pull request.

## License

dr_source is licensed under the MIT License.

## Acknowledgments

Special thanks to the maintainers of
[javalang](https://github.com/c2nes/javalang) for their work on Java AST
parsing, which powers the Java taint analysis plugin.
