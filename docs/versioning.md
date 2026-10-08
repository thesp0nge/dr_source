# Versioning and releases

DRSource uses Semantic Versioning with an explicit convention during the pre-1.0
period: `0.MINOR.PATCH`. Continue the existing numbering sequence; do not reset
it to `0.18.0`, `0.19.0`, or another shorter sequence.

## Current release train

- Current released version: `0.171.0`.
- Intended next capability release: `0.172.0`.
- Possible compatible fixes afterward: `0.172.1`, `0.172.2`.

The current unreleased work on project symbol identity, call resolution, plugin
lifecycle, and resolution diagnostics/provenance belongs to the `0.172.0` release
train. **`0.172.0` is a target, not a released version.** The package remains at
`0.171.0` until release preparation. An installed editable checkout can therefore
report `0.171.0` while containing unreleased work.

## Choosing a version

Increment **MINOR**, resetting PATCH to zero, for significant new capability,
meaningful architectural evolution, public API or plugin-contract changes,
public configuration/output contract changes, or intentionally breaking pre-1.0
changes. Examples: `0.171.0 -> 0.172.0`, then `0.172.0 -> 0.173.0`.

Increment **PATCH** for bug fixes, correctness fixes, compatible regression
fixes, or documentation/release corrections when a release is warranted, without
intentionally introducing a new public capability or breaking public contracts.
Examples: `0.172.0 -> 0.172.1 -> 0.172.2`. Changes to tests alone do not require
a version bump. Choose according to the most significant change in a release;
a capability release can also include fixes.

Pre-1.0 APIs may evolve, but breaking changes must be deliberate and explicitly
documented in the changelog and relevant integration/API documentation. Describe
the compatibility impact and migration steps; `0.x` is not permission to break
contracts silently.

Release **1.0.0** only as an intentional compatibility commitment covering at
least CLI behavior, AnalyzerPlugin/public APIs, configuration and rule contracts,
principal output/report formats, and documented integration behavior. Usefulness
or maturity alone is insufficient. Define the supported contracts and migration
policy before making that commitment. After 1.0, incompatible public contract
changes require a MAJOR increment under Semantic Versioning.

## Version source of truth

`pyproject.toml`'s `[project].version` is the canonical package version. Bumps
occur during release preparation, not ordinary feature work. This repository
currently has no separate development-version bump policy.

Runtime consumers obtain the installed distribution version through
`importlib.metadata.version("dr_source")`, retaining the existing
`importlib_metadata` fallback where needed. Do not copy the version into
production/reporting constants or a manually maintained `__version__`.
Reinstall/rebuild after a metadata change before verifying runtime output.

The CLI and SARIF reporter each perform a small metadata lookup. A central
helper is not needed for these two simple consumers: neither maintains an
independent version value, and the CLI's existing behavior remains intact.
SARIF reports `unknown` if installed distribution metadata is unavailable,
rather than inventing a package version. Its SARIF format version (`2.1.0`)
is independent of the DRSource tool version.

## Changelog and tags

New work belongs under `[Unreleased]` in `CHANGELOG.md`, using Keep a Changelog
categories such as Added, Changed, and Fixed. Record significant, verified
behavior and compatibility implications; avoid unsupported capability claims.
Do not edit released sections to describe later work. Only release-preparation
tasks may move unreleased entries into a versioned, dated section.

New release tags use **`vX.Y.Z`**, for example `v0.172.0`, and are annotated.
Do not use `0.172`, `0.172.0`, or `release-0.172.0` for new release tags.
Historical tags are never renamed merely to normalize history; the existing
mixture of prefixed and unprefixed tags remains intact.

## Release preparation and publication

This is the intended procedure for an explicitly authorized release task.
Documenting it does not authorize publication during ordinary development.

1. Ensure the main/target branch is green.
2. Review `[Unreleased]`, including compatibility and migration notes.
3. Choose the version according to the MINOR/PATCH/MAJOR policy.
4. Update `[project].version` in `pyproject.toml`.
5. Move `[Unreleased]` entries to `[X.Y.Z] - YYYY-MM-DD`, using the actual
   release date.
6. Recreate an empty `[Unreleased]` section above that release.
7. Run the full test suite with `pytest -q`.
8. Build the source distribution and wheel, for example with `python -m build`
   in a release environment with the build frontend installed.
9. Verify both built artifacts' metadata versions against `[project].version`;
   install the wheel in a clean environment and verify runtime/CLI reporting
   against installed package metadata. Check that the intended artifacts are
   the ones being published.
10. Commit release preparation.
11. Create an annotated tag `vX.Y.Z` at the release-preparation commit.
12. Create the GitHub Release for that tag, with release notes and artifacts.
13. Publish the verified artifacts to PyPI.

The next capability release should follow this procedure for `0.172.0` when
explicitly cut. Do not create a dated `0.172.0` changelog section or bump the
package in advance merely to mark the release target.

## Future release automation

The repository currently has `.github/workflows/tests.yml`, which runs tests
on main-branch pushes and pull requests with Python 3.9, 3.11, and 3.13. There
is no release workflow: tag/version validation, artifact builds, GitHub Releases,
and PyPI publication are not automated by it.

A future GitHub Actions release workflow should:

- Trigger on release tags matching `vX.Y.Z` and validate that the tag's numeric
  version exactly matches `[project].version` before publication.
- Run the tests, build the source distribution and wheel, and verify artifact
  metadata against the selected version.
- Publish build artifacts and create/populate the GitHub Release.
- Publish to PyPI through Trusted Publishing with OIDC, using a configured
  trusted publisher and appropriately scoped workflow/environment permissions.

Do not add long-lived PyPI tokens or repository secrets as part of this policy.
Release automation is future work; this policy does not introduce a workflow
or perform any release operation.

## Version-source audit

The audit establishing this policy found these categories:

| Occurrences | Classification and action |
| --- | --- |
| `pyproject.toml [project].version` | Canonical package metadata; remains `0.171.0`. |
| CLI `--version` | Runtime consumer of installed package metadata; unchanged. |
| SARIF `tool.driver.version = "1.0.0"` | Incorrect hardcoded DRSource runtime version; replaced with installed package metadata. |
| SARIF `version = "2.1.0"` and schema URL | Legitimate SARIF format identifiers; unchanged. |
| `dr_source/__init__.py` | No `__version__` or separate version constant. |
| Changelog releases and denominator-investigation runtime versions | Historical documentation; preserved. |
| Dependency analyzer version fields and dependency fixtures (`requests`, Maven) | Unrelated dependency versions/test fixtures; preserved. |
| Scanner/plugin tests using `importlib.metadata.entry_points` | Plugin discovery, not package-version reporting; preserved. |
| Audit helper using `importlib.metadata.version` | Investigation metadata for DRSource and dependencies; already uses installed metadata. |

No other hardcoded DRSource runtime version or report-version consumer was
found. Focused version-reporting tests compare CLI/SARIF output with installed
package metadata rather than a literal release number; no network is required.
