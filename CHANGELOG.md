# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [unreleased]

### Added

- Implementing data flow analysis and taint propagation
- Added detectors for:
  - open redirect
  - insecure cookie settings
  - insecure reflection
  - insecure file inclusion
  - deprecated API (just few apis by now, adding more it would be trivial)
  - jndi injection
  - session fixation
  - information disclosure  

- New ASCII tabular formatted report

### Modified

- Regex for hardcoded credential detectors

## [0.71.0] - 2025-02-18

### Fixed

- Fix an issue with database path.

## [0.70.0] - 2025-02-1

### Added

- Version bump to 0.70 and make the project public on pypi.org
- Initial changes tracking with a Changelog file
