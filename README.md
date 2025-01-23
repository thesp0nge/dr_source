# DRSource: Java Vulnerability Static Analyzer

## Overview

DRSource is a comprehensive static code analysis tool for detecting security vulnerabilities in Java and JSP projects.

## Features

- Vulnerability detection for Java and JSP files
- Multiple vulnerability type scanning
- Extensible pattern matching
- Detailed reporting
- CLI interface

## Installation

``` sh
pip install .
```

## Usage

``` sh
drsource /path/to/java/project
# Optional output file
drsource /path/to/java/project -o report.json
```

## Supported Vulnerability Types

XSS (Cross-Site Scripting)
SQL Injection
Command Injection
Path Traversal
Deserialization Risks
Sensitive Data Exposure

## Configuration

Customize vulnerability detection by modifying detection patterns in the source code.

## Contributing

Open issues and pull requests are welcome.

## License
