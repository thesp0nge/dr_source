# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.95.2] - 2025-11-17

### Added

Implemented full taint-propagation tracing for the PythonAstAnalyzer. The plugin
now generates and stores the complete data flow (e.g., "Tainted by source ->
Propagated to var -> Used in sink").

Added new test cases to test_python_ast_analyzer.py to validate taint
propagation through string concatenation (BinOp) and f-strings (JoinedStr).

The Vulnerability object in dr_source/api.py now includes a trace: List[str]
field.

The ScanDatabase schema and Scanner logic have been upgraded to store and
retrieve taint traces.

### Changed

The PythonTaintVisitor has been significantly upgraded from a simple set to a
dictionary that tracks the full trace for each tainted variable.

The cli.py output for --show-trace will now work for Python-based findings.

## [0.95.1] - 2025-11-17

### Changed

Optimized the RegexAnalyzer to be language-aware. It now loads rules into
language-specific buckets (e.g., .py, .java) and only runs the relevant rules
for each file.

### Fixed

Fixed a bug where the RegexAnalyzer would run language-specific rules (e.g., for
Java) against all file types, which could lead to false positives and poor
performance. This is confirmed by a new test case
(test_java_rules_do_not_run_on_python_files).

## [0.95.0] - 2025-11-10

### Added

- New Python AST Analyzer Plugin: Added a new, fully-featured PythonAstAnalyzer
  plugin to support multi-language taint analysis.
- Python Taint Propagation: The new Python visitor (PythonTaintVisitor) supports
  taint propagation through:
- Variable assignments (a = b)
- Binary Operations ("ping " + tainted_var)
- F-strings (f"SELECT \* FROM {tainted_var}")
- Python Test Suite: Added a complex test suite (complex_vulnerable_app.py) to
  validate Python taint propagation for SQLi and Command Injection.
- Modern Packaging: Migrated the entire project from setup.py and
  requirements.txt to a single, modern pyproject.toml file (PEP 621).

### Changed

- Knowledge Base: Massively expanded knowledge_base.yaml to include
  Python-specific ast_sources and ast_sinks for all relevant vulnerability
  categories.

- Knowledge Base: Added dozens of new Python-specific regex_patterns for all
  vulnerability types (e.g., SSRF, XSS, Weak Crypto, Insecure Cookies).

- Python AST Visitor: The PythonTaintVisitor's \_get_full_call_name helper was
  made more robust to accurately find fully-qualified function calls (e.g.,
  request.args.get) and minimize false positives.

### Removed

- setup.py: This file is now obsolete and has been replaced by pyproject.toml.
- requirements.txt: Project dependencies are now managed in pyproject.toml.
- bin/dr_source: The CLI entry point is now defined in pyproject.toml under
  [project.scripts].

## [0.90.1] - 2025-11-07

### Changed

- Moving to pyproject.toml file in order to meet PEP621 standard

## [0.90.0] - 2025-11-07

This release marks a fundamental rewrite of DRSource, moving from a monolithic
Java-only scanner to an extensible, multi-language, plugin-based platform.

### Added

- Plugin-Based Architecture: The core scanner is now a lightweight orchestrator
  that discovers and runs all available "Analyzer Plugins."
- Centralized Knowledge Base: All detection rules (both Regex and AST
  taint-tracking) are now defined in a single, human-readable
  knowledge_base.yaml.

- New RegexAnalyzer Plugin: A single, powerful, data-driven plugin that replaces
  the entire old dr_source/core/detectors/ directory. It reads all regex rules
  from the new knowledge base.

- Multi-language Foundation: The architecture and knowledge base are now
  designed to easily support new languages (e.g., Python, Go) by simply adding a
  new plugin.

- External Rule Loading: The KnowledgeBaseLoader can load custom
  knowledge_base.yaml files from user (~/.config/dr_source/) or system
  (/etc/dr_source/) directories, making it easy to extend.

- dr_source.api: A formal API (AnalyzerPlugin) for creating new analysis
  plugins.

- Database Enhancements: The database schema has been upgraded to store
  severity, plugin_name, and full trace information for all findings.

### Changed

- Major Refactor: The Scanner (dr_source/core/scanner.py) has been rewritten as
  a plugin orchestrator. It no longer contains any detection logic itself.

- Java AST Analyzer (Plugin): The Java AST and Taint Analysis logic (formerly
  taint_detector.py, taint_visitor.py) has been refactored out of core and into
  its own self-contained plugin: dr_source.plugins.java.JavaAstAnalyzer.

- Rule Migration: All detection logic (SQLi, XSS, JNDI, Open Redirect, Insecure
  Cookie, Reflection, etc.) has been migrated from old, hardcoded Python files
  into the new knowledge_base.yaml.

- CLI Update: The cli.py has been updated to call the new Scanner. It now
  fetches results directly from the database for reporting.

- Taint Visitor: The TaintVisitor is now fully data-driven, receiving its list
  of sources and sinks directly from the Knowledge Base.

### Removed

- --ast flag: This flag is now obsolete and has been removed. The scanner now
  runs all available plugins (AST, Regex, etc.) by default on every scan,
  providing more comprehensive results without needing a special mode.

- dr_source/core/detectors/: This entire directory and all its individual
  detector files have been deleted. This logic is now handled by the
  RegexAnalyzer plugin.

- dr_source/core/detection_rules.py: The old singleton rule loader has been
  deleted and replaced by dr_source/core/knowledge_base.py.

## [0.71.0] - 2025-02-18

### Fixed

- Fix an issue with database path.

## [0.70.0] - 2025-02-1

### Added

- Version bump to 0.70 and make the project public on pypi.org
- Initial changes tracking with a Changelog file
