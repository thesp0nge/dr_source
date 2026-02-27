# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.111.0] - 2026-02-27

### Added
- **Professional CLI Output:**
  - Implemented a clean, color-coded interface using `click` styles.
  - Added a **Scan Summary Table** at the end of each scan, showing files analyzed, duration, and issue counts by severity.
  - Vulnerability findings are now highlighted with colors (e.g., Red for HIGH, Yellow for MEDIUM) for better readability.
  - Data-flow traces are now properly formatted and visually distinguished.

### Changed
- **Noise Reduction (Logging):**
  - Moved all internal "INFO" logs (plugin loading, knowledge base merging, function registration, regex compilation) to "DEBUG" level.
  - The CLI now only displays progress bars and security findings by default, providing a high-signal experience.
  - Removed redundant "Starting scan" and "Scan completed" messages.

## [0.110.0] - 2026-02-27

### Added
- **Semgrep-Compatible Boolean Engine:**
  - Implemented a recursive logical evaluator for pattern matching.
  - Support for `patterns` (AND), `pattern-either` (OR), and `pattern-not` (NOT) operators in the Knowledge Base.
- **Metavariable Unification:**
  - Upgraded the pattern matching engine to support real metavariable unification ($X, $Y).
- **Constant Propagation & Literal Tracking:**
  - Implemented a data-flow constant propagation engine for Python, Java, and JavaScript.
  - **False Positive Reduction:** Taint analysis now ignores "sinks" that receive known safe constant values.
- **Multi-Language Pattern Matching:**
  - Extended the `PatternAnalyzer` to support Java and JavaScript using Tree-sitter.
- **Expanded Knowledge Base:**
  - Added NoSQL Injection, SSTI, XXE, Open Redirect, Prototype Pollution, Insecure Randomness.

### Fixed
- **JavaScript Sink Detection:** Fixed detection of property-based sinks like `innerHTML`.
- **Pattern Matcher Duplication:** Resolved double-reporting of call expressions wrapped in expression statements.
- **Plugin Loading:** Fixed `NameError` and `AbstractMethodError` in `PatternAnalyzer`.

## [0.104.0] - 2026-02-26
...
