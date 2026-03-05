# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.170.0] - 2026-03-05

### Added

- **Universal Field-Sensitive Taint Analysis:**
  - Implemented deep object property tracking for **Python, Java, JavaScript,
    PHP, and Ruby**.
  - The engine now correctly handles assignments like `obj.attr = tainted` and
    distinguishes between safe and tainted fields within the same object.
  - Full support for nested properties (e.g., `user.profile.name`) and recursive
    path resolution.
- **Advanced Framework Intelligence:**
  - **Django Support:** Heuristic detection of `request` objects and structural
    analysis of `ModelForm` to detect Mass Assignment (`fields = '__all__'`).
  - **FastAPI Support:** Support for `async def` routes and automatic parameter
    source detection.
  - **Ruby on Rails Support:** Deep tracking of `params[]` and mapping of
    ActiveRecord `create/update` sinks.
  - **Java Enterprise Support:** Full mapping for Spring Boot, Jakarta EE
    Servlets, Hibernate/JPA, and JAX-RS.
- **Massive Knowledge Base Expansion (Supreme Edition):**
  - **RCE Protection:** Added Insecure Deserialization (all languages) and
    expanded SSTI (Jinja2, Twig, EJS, ERB).
  - **Compliance & Crypto:** Added Weak Cryptography (MD5, SHA1, AES-ECB) and
    Insecure JWT (verify=False, none algorithm).
  - **Logic Vulnerabilities:** Implemented Mass Assignment detection and
    Insecure Token Generation (predictable random for passwords).
  - **Data Safety:** New PII Leakage category using semantic heuristics on
    variable names (e.g., `email`, `password`).
  - **LFI/RFI Support:** Dedicated PHP `include/require` statement analysis.
- **Robust Taint Propagation:**
  - Added support for Python f-string (`JoinedStr`) and call chaining (e.g.,
    `db.cursor().execute()`).
  - Improved Ruby argument extraction for methods called without parentheses.
  - Suffix-based sink matching implemented for all languages to handle various
    object receivers.

### Fixed

- **Global Deduplication:** Implemented a unique-key system in the core Scanner
  to prevent duplicate findings across multiple analyzer passes.
- **Regex Optimization:** Refactored `RegexAnalyzer` to use a per-line set
  tracking, eliminating redundant reports for the same rule on the same line.
- **API Integrity:** Standardized all plugins to strictly follow the
  `AnalyzerPlugin` interface, fixing various runtime attribute errors.
- **JavaScript Sink Detection:** Fixed property assignment sinks like
  `innerHTML` being ignored.

## [0.150.0] - 2026-03-04

### Added

- **Field-Sensitive Taint Analysis (All Core Languages):**
  - The taint engine now tracks data-flow at the property/field level (e.g.,
    `user.name` vs `user.id`) for **Python, Java, JavaScript, PHP, and Ruby**.
  - If a specific field is tainted, only sinks using that exact field are
    flagged, drastically reducing false positives.
  - Supports recursive path resolution: if an entire object is tainted, all its
    sub-fields are considered tainted.
- **Python Framework Support (FastAPI & Django):**
  - Introduced `PythonFrameworkMapper` to handle framework-specific decorators
    and parameter injection.
  - **FastAPI:** Automatic detection of route parameters as sources in functions
    decorated with `@app.get`, `@app.post`, etc., including `async def` support.
  - **Django:** Heuristic detection of the `request` object as a primary data
    source in views, with full attribute (`request.GET`) and subscript
    (`request.GET['id']`) propagation.
- **Java Multi-Framework Support:**
  - Introduced `JavaFrameworkMapper` architecture to handle framework-specific
    entry points and sinks cleanly.
  - **Spring Boot:** Support for `@RequestParam`, `@PathVariable`,
    `@RequestBody`, and `JdbcTemplate` sinks.
  - **Jakarta EE / Servlets:** Automatic detection of `request.getParameter()`,
    `getHeader()`, etc., as sources.
  - **JAX-RS:** Support for REST annotations like `@QueryParam` and
    `@PathParam`.
  - **Hibernate / JPA:** Support for tracing taint into
    `EntityManager.createQuery()` and `Session.createNativeQuery()`.
- **Enhanced Taint Engines:**
  - **Python:** Full support for f-string (`JoinedStr`) propagation and call
    chaining (e.g., `db.cursor().execute()`).
  - **Java:** Improved inter-procedural analysis to handle local method calls
    even when defined after their usage.
  - **Multi-language:** Robust parameter mapping during call simulation and
    suffix-based sink matching.

### Fixed

- **JavaScript Sink Detection:** Fixed a bug where property assignments (e.g.,
  `element.innerHTML = ...`) were not being tracked by the taint engine.
- **Ruby Method Call Detection:** Improved robustness in extracting method names
  and handling string interpolations.
- **Dependency Analysis:** Fixed `pip-audit` detection in virtual environments.

## [0.112.0] - 2026-02-27

### Added

- **Full PHP & Ruby Support:**
  - Implemented AST-based Taint Analysis plugins for PHP and Ruby using
    Tree-sitter.
  - Added specialized visitors to track data-flow from superglobals (`$_GET`,
    `$_POST`), `params`, and `cookies`.
  - Added support for Ruby string interpolation (`#{var}`) and PHP array access
    in taint propagation.
- **Semgrep-Compatible Boolean Engine:**
  - Implemented a recursive logical evaluator for pattern matching.
  - Support for `patterns` (AND), `pattern-either` (OR), and `pattern-not` (NOT)
    operators in the Knowledge Base.
  - Enabled sophisticated rule definitions that combine multiple conditions and
    exclusions.
- **Advanced Metavariable Unification:**
  - Upgraded the pattern matching engine to support real metavariable
    unification (`$X`, `$Y`).
  - The engine now ensures that multiple occurrences of the same metavariable
    within a pattern must match identical AST nodes.
- **Constant Propagation & Literal Tracking:**
  - Implemented a data-flow constant propagation engine for Python, Java,
    JavaScript, PHP, and Ruby.
  - Automatically identifies and ignores safe hardcoded literals and their
    simple concatenations in security sinks, drastically reducing false
    positives.
- **Professional CLI UX:**
  - **Color-Coded Output:** Vulnerabilities are now displayed with colors based
    on severity (Critical, High, Medium, Low).
  - **Detailed Summary Table:** Added an elegant summary table at the end of
    every scan showing files analyzed, duration, and issue counts.
  - **Log Noise Reduction:** Internal informational messages moved to `DEBUG`
    level for a cleaner "product-like" experience.
- **Knowledge Base Expansion:**
  - Added dozens of new rules for modern vulnerabilities: NoSQL Injection
    (MongoDB), SSTI (Jinja2, EJS, Twig, ERB), XXE, Open Redirect, and Prototype
    Pollution.
  - Improved coverage for framework-specific APIs (Spring Boot, Django, Express,
    Rails).

### Fixed

- **JavaScript Sink Detection:** Fixed a bug where property assignments (e.g.,
  `element.innerHTML = ...`) were not being tracked by the taint engine.
- **Ruby Method Call Detection:** Fixed an issue where method calls with
  receivers (e.g., `User.find_by_sql`) were sometimes missed by the visitor.
- **PHP Parsing:** Improved parsing of PHP code fragments by automatically
  handling missing open tags (`<?php`).
- **Pattern Matcher Robustness:** Fixed double-reporting of findings and
  implemented a smart textual fallback for complex AST structures.

## [0.111.0] - 2026-02-26

### Added

- Initial support for Tree-sitter in core engines.
- Base Pattern Matcher plugin for Python.

## [0.104.0] - 2026-02-26

### Added

- **Keyboard Interrupt Skip Shortcut:**
  - Implemented a "Skip File" shortcut using `Ctrl+C`.
  - Pressing `Ctrl+C` once during the indexing or analysis of a file will now
    interrupt only that specific file and skip to the next one, rather than
    aborting the entire scan.
  - Added a "Double Ctrl+C" protection: if `Ctrl+C` is pressed twice within 2
    seconds, the scan will be aborted completely. This provides a user-friendly
    way to skip slow/stuck files while maintaining the ability to exit.

### Fixed

- **Scanner Lifecycle Test:** Updated `tests/test_scanner.py` to correctly
  reflect the current number of test files (5 instead of 3), fixing an
  `AssertionError` in the CI/test suite.

## [0.103.0] - 2026-02-26

### Added

- **Per-File Timeout Mechanism:**
  - Implemented a new timeout system that monitors the indexing and analysis of
    individual files.
  - If a file takes too long to process (e.g., due to complex AST structures or
    recursive flows), the scanner will log an error, skip the problematic file,
    and continue with the rest of the codebase.
  - This ensures that a single "hanging" file does not block the entire scanning
    process.
- **CLI --timeout Option:**
  - Added a new `--timeout <seconds>` option to the main CLI.
  - Users can specify the maximum duration allowed for each file's indexing and
    analysis phases separately.
  - Default is `0` (no timeout).

### Changed

- **Scanner Robustness:** Updated the core scanner to gracefully handle
  `TimeoutException` and `KeyboardInterrupt` during plugin execution.

## [0.102.0] - 2026-02-25

### Added

- **Full Inter-File Analysis:**
  - **Global Project Indexing:** The scanner now performs a pre-scan phase to
    index all functions and methods across the entire codebase.
  - **Cross-File Taint Tracking:** Taint analysis can now follow data flows
    across file boundaries. When a function from another file is called with
    tainted data, the engine "jumps" into that file's AST to continue the
    analysis.
  - **Cross-Language Support:** Inter-file analysis is fully implemented for
    Java (Tree-sitter), Python (Native AST), and JavaScript/Node.js
    (Tree-sitter).
- **Professional Taint Analysis Engine:**
  - **Scope Management:** Implemented a scope stack (stack of dictionaries) in
    all AST visitors. This ensures variable name collisions between different
    functions or blocks do not cause cross-contamination of taint.
  - **AST Sanitizers Support:** The engine now recognizes "Sanitizer" methods
    (e.g., `int()`, `escape()`, `prepareStatement`). If tainted data passes
    through a sanitizer, the taint is removed.
  - **Sink Argument Tracking:** Knowledge base rules can now specify which
    arguments are vulnerable (e.g., `args: [0]`). Findings are only reported if
    tainted data reaches a vulnerable argument.
  - **Suffix-Based Sink Matching:** Support for matching sinks by suffix (e.g.,
    matching `cp.exec` against a rule for `child_process.exec`).
- **Enhanced Knowledge Base:**

  - Massively expanded rules for Java, Python, and JavaScript/Node.js.
  - Added high-entropy regex patterns for modern secrets (AWS, GitHub, Stripe,
    etc.).
  - Comprehensive support for Node.js ecosystems (Express, Sequelize, Prisma,
    Axios).

- **New Pattern Matching Engine:** Introduced a new `PatternAnalyzer` plugin for
  Python, enabling Semgrep-like pattern matching for more expressive and
  powerful security rules.
- **Metavariable Support:** The pattern matching engine now supports
  metavariables (e.g., `$VAR`) to match any single expression or statement.
- **Ellipsis Support:** The pattern matching engine now supports ellipsis
  (`...`) to match any sequence of arguments or statements.
- **New Rules:** Added new rules `INSECURE_EVAL` and `INSECURE_PRINT` to the
  `knowledge_base.yaml` to demonstrate the new pattern matching capabilities.

### Changed

- **Scanner Workflow:** Added an "Indexing Phase" before the "Analysis Phase" to
  build the global symbol table.
- **Reporting:** Taint traces now include cross-file hops (e.g.,
  `Passed to helper() in Utils.java at line 45`).
- **Plugin API:** Added an optional `index()` method to the `AnalyzerPlugin`
  interface.
- **Scanner File Collection:** The scanner can now correctly handle both single
  file paths and directory paths as input targets.

### Fixed

- **File Scanning Logic:** Fixed a bug where the scanner would not analyze any
  files when a single file path was provided as a target.
- **Logging Configuration:** Resolved several issues with the logging
  configuration to ensure debug messages are correctly displayed when the
  `--debug` flag is used.

## [0.101.0] - 2025-11-20

### Added

Multi-Layer Knowledge Base (Configuration Overlays): The Knowledge Base
(knowledge_base.yaml) now automatically merges rules from multiple locations,
allowing for user overrides.

Search Priority: Rules are loaded in ascending priority (low to high): Factory
Default -> User Home (~/.config/dr_source/) -> Local Project
(.dr_source_rules.yaml) -> Explicit CLI Path.

deep_merge Utility: Added the core recursive utility to handle merging complex
dictionaries and extending lists (like rule patterns and ast_sources) without
losing data.

### Changed

KnowledgeBaseLoader Refactor: The loader now uses a multi-path search sequence
and applies deep merging on every file, ensuring the highest priority rule wins
any conflict.

## [0.100.0] - 2025-11-20

### Added

New JavaScript AST Analyzer Plugin: Added a new plugin dedicated to deep
analysis of JavaScript and TypeScript code (Node.js/Browser).

JavaScript Taint Analysis: Implements flow tracking from request sources
(req.query, req.body, document.location) to dangerous sinks (eval, innerHTML,
child_process.exec).

Robust JS Parsing: Uses the tree-sitter-javascript grammar for reliable parsing
of modern JavaScript syntax (ES2023+).

Expanded Knowledge Base: Updated the knowledge_base.yaml file with new
JavaScript AST sources and sinks for XSS and Command Injection.

### Changed

Dependencies: Added tree-sitter-javascript to the dependencies.

## [0.99.0] - 2025-11-19

### Added

Project History Command: Implemented the new --list-scans command. This feature
scans the dr_source database directory, lists all projects that have been
scanned, and displays a summary of the total scan count, last scan date, and the
final vulnerability count for each project. Dependency: Added tabulate
dependency for cleanly formatted ASCII table output in the console.

### Modified

Database: Added ScanDatabase.list_all_project_scans() method to aggregate data
across multiple project databases. CLI: Refactored argument parsing and
reporting to handle the new command.

## [0.98.0] - 2025-11-19

### Added

Progress Bar for Scanning: Implemented the tqdm library to display a real-time
progress bar during file analysis. This provides immediate user feedback on
scanning progress and time estimation, preventing the tool from appearing
"stuck" on large directories.

### Changed

Scanner Refactor: The core Scanner.scan() method was refactored into two
distinct phases (File Collection and Analysis) to accurately count the total
number of files to be processed, enabling the progress bar functionality.

Dependencies: Added tqdm to the project dependencies.

## [0.97.0] - 2025-11-18

### Changed

Major Refactor: The JavaAstAnalyzer plugin has been completely rewritten to use
Tree-sitter instead of javalang. This provides robust support for modern Java
features (Java 10+ var, text blocks, records, etc.) that previously caused
scanning errors.

Dependency: Replaced javalang with tree-sitter and tree-sitter-java for Java
parsing.

### Fixed

Java Parsing Errors: Fixed recurring "Could not parse Java file" errors on
modern Java codebases.

Taint Tracking Accuracy: Fixed logic in TaintVisitor to correctly normalize
source/sink names from the Knowledge Base (e.g., handling request.getParameter
vs getParameter), ensuring vulnerabilities are not missed due to naming
mismatches.

Stability: Resolved multiple AttributeError and TypeError crashes in the Java
taint analysis engine (Assignment node handling, missing arguments).

## [0.96.1] - 2025-11-18

### Fixed

Java AST Analyzer Crash: Fixed an AttributeError in the Java taint visitor where
Assignment nodes were accessing the non-existent expression attribute. Updated
logic to use the correct javalang attribute expressionl.

Taint Detection Logic: Fixed a TypeError in TaintDetector by correctly passing
the AST tree to the get_vulnerabilities method.

## [0.96.0] - 2025-11-18

### Added

New DependencyAnalyzer Plugin: Added a dedicated plugin for Software Composition
Analysis (SCA) to detect known vulnerabilities in third-party dependencies.

Python Dependency Scanning: Support for scanning requirements.txt files. Uses
pip-audit to check packages against the PyPI/OSV vulnerability database.

Java Dependency Scanning: Support for scanning Maven pom.xml files. It parses
dependencies via xml.etree and queries the OSV (Open Source Vulnerability) API
directly to find CVEs.

pip-audit Dependency: Added pip-audit to the project dependencies in
pyproject.toml.

## [0.95.2] - 2025-11-17

### Added

Implemented full taint-propagation tracing for the PythonAstAnalyzer. The plugin
now generates and stores the complete data flow (e.g., "Tainted by source ->
Propagated to var -> Used in sink").

Added new test cases to test_python_ast_analyzer.py to validate python taint
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
