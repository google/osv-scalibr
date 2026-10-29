# Guided Remediation

Package `guidedremediation` provides vulnerability fixing through dependency
updates in manifest and lockfiles. It supports various ecosystems and offers
both programmatic and interactive modes.

> [!WARNING]
> Guided remediation can be risky when run on untrusted projects. It may trigger
> the package manager to execute scripts or follow external registries specified
> in the project. Please ensure you trust the source code and artifacts before
> proceeding.

### Unsafe Python lockfile generation

Native Python lockfile generation is disabled by default. To permit it, library
callers must explicitly set `options.FixVulnsOptions.AllowUnsafeExecution = true`.
Without this opt-in, requests to regenerate Python lockfiles fail before
dependency resolution or file modification. Manifest-only Python remediation
does not require this option; npm continues to disable lifecycle scripts with
`--ignore-scripts`.

The opt-in allows `pip-compile`, `poetry lock`, and `pipenv lock` to execute
dependency build hooks (including `setup.py`) or package-manager plugins with
the caller's privileges. It does **not** sandbox these tools. Only enable it for
trusted projects and dependencies, or inside an appropriately isolated
environment without access to host credentials or other sensitive resources.
Existing lockfile format support is unchanged; opting in does not add support
for reading Poetry or Pipenv lockfiles. Interactive behavior is unchanged.

## Overview

This package is part of the SCALIBR library and handles the **remediation**
step of vulnerability management. It analyzes the entire dependency graph
(leveraging dependency resolution) to suggest minimal changes needed to
remove vulnerabilities.

Once vulnerabilities are identified, this package can attempt to fix them by
modifying the project's dependency files (manifests or lockfiles).

## Supported Ecosystems and Files

| Language | Ecosystem | Manifests | Lockfiles |
| :--- | :--- | :--- | :--- |
| JavaScript | npm | `package.json` | `package-lock.json` |
| Java | Maven | `pom.xml` | N/A |
| Python | pip | `requirements.in`, `requirements.txt` | `requirements.txt` |
| Python | Poetry | `pyproject.toml` | `poetry.lock` |
| Python | Pipenv | `Pipfile` | `Pipfile.lock` |

> [!NOTE]
> For Python `pip`, `requirements.in` is treated as the manifest (input) and
> `requirements.txt` as the lockfile (compiled output). However, a standalone
> `requirements.txt` can also be treated as a manifest depending on usage.

## Project Boundary

Guided remediation confines manifest and lockfile access to a project boundary.
Set `ProjectRoot` to choose this boundary explicitly. If it is empty, guided
remediation uses the nearest enclosing Git repository root and falls back to the
directory containing the selected manifest or lockfile when no Git repository
is found. Files outside this boundary, including Maven parent POMs, are not read
or updated.

## Remediation Strategies

Strategies are defined in the `guidedremediation/strategy` subpackage:

- **`in-place`**: Updates the version directly, for lockfiles.
- **`relax`**: Relaxes version constraints in the manifest to allow newer
  versions.
- **`override`**: Uses ecosystem-specific override mechanisms to force a
specific version.
