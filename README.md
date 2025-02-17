# DRSource

DRSource is a static analysis tool designed to detect vulnerabilities in Java and JSP projects. It combines multiple detection techniques—including regex‑based detection and AST‑based taint propagation analysis—to identify security issues such as SQL Injection, Cross‑Site Scripting (XSS), Path Traversal, Command Injection, Serialization Issues, LDAP Injection, XXE, SSRF, and unsafe cryptographic/hashing functions.

## Features

- **Regex‑Based Detection**  
  Utilizes carefully crafted regular expressions to identify known vulnerability patterns in source code.

- **AST‑Based Taint Analysis**  
  Leverages [javalang](https://github.com/c2nes/javalang) to parse Java source files into an Abstract Syntax Tree (AST) and performs forward data‑flow analysis to propagate taint from user input sources (e.g., `request.getParameter`) to sensitive sinks (e.g., `executeQuery`).

- **Data‑Flow Analysis Framework**  
  A simplified yet robust framework that tracks tainted variables through declarations and assignments to flag dangerous data flows.

- **Multi‑Detector Support**  
  Detects various vulnerabilities including:
  - SQL Injection
  - Cross‑Site Scripting (XSS)
  - Path Traversal
  - Command Injection
  - Serialization Issues
  - LDAP Injection
  - XXE (XML External Entity) Attacks
  - SSRF (Server-Side Request Forgery)
  - Unsafe Crypto/Hashing functions

- **Parallel Scanning & Progress Bar**  
  Files are scanned in parallel with a progress bar for faster analysis on large codebases.

- **Robust CLI**  
  The command‑line interface offers options to:
  - Initialize the database (`--init-db`)
  - View scan history (`--history`)
  - Compare scans (`--compare`)
  - Export results in SARIF, JSON, or HTML formats (`--export`)
  - Enable AST‑based detection (`--ast`)
  - Enable debug logging (`--debug`)
  - Display version information (`--version`)

## Installation

Clone the repository and navigate to the project root:

```bash
git clone https://github.com/thesp0nge/dr_source.git
cd dr_source
```

Install the package in editable mode:

```bash
pip install --editable .
```

## Usage

Run dr_source using the CLI:

```bash
dr_source [OPTIONS] TARGET_PATH
```

### Options

- TARGET_PATH: The path of the codebase (directory containing Java/JSP files) to analyze.
- --init-db: Initialize the database from scratch (drops and recreates tables).
- --history: Display the scan history for the project.
- --compare <ID>: Compare the latest scan with a previous scan specified by ID.
- --export [sarif|json|html]: Export scan results in the specified format.
- --ast: Enable AST‑based detection (in addition to regex‑based detection).
- --debug: Enable debug logging.
- --version: Show DRSource version (as defined in setup.py) and exit.

### Examples

- Scan a Codebase Using AST‑Based Detection with Debug Logging:

```bash
dr_source --ast --debug /path/to/codebase
```

- Initialize the Database:

```bash
dr_source --init-db /path/to/codebase
```

- Export Results as SARIF:

```bash
dr_source --export sarif /path/to/codebase
```

## Contributing

Contributions are welcome! To contribute:

- Fork the repository.
- Create a new branch for your feature or bugfix.
- Make your changes with clear commit messages.
- Submit a pull request for review.
- For major changes, please open an issue first to discuss your proposed changes.

## License

dr_source is licensed under the MIT License.

## Acknowledgments

Special thanks to the maintainers of [javalang](https://github.com/c2nes/javalang) for their work on Java AST parsing.
Inspired by various static analysis and security tools.
