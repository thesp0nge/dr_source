# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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
