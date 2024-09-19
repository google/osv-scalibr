# Supported inventory types

SCALIBR supports extracting software package information from a variety of OS and language package managers. See below for the comprehensive list. Some of these are supported by reusing extraction code from Google's [OSV-Scanner](https://github.com/google/osv-scanner).

## OS packages

* Alpine
  * APK
* COS
  * cos-package-info.json
* DPKG (used by e.g. Debian, Ubuntu)
* RPM (used by e.g. RHEL, CentOS, Rocky Linux)
* SNAP
* Flatpak
* Homebrew (used by OS X)

## Language packages

* .NET
  * packages.lock.json
* C++
  * Conan packages (OSV)
* Dart
  * pub packages (OSV)
* Go
  * Go binaries
  * go.mod (OSV)
* Java
  * Java archives
  * Lockfiles (OSV): pom.xml, gradle.lockfile
* Javascript
  * Installed NPM packages (package.json)
  * Lockfiles: package-lock.json, yarn.lock (OSV), pnpm-lock.yaml
* PHP:
  * Composer (OSV)
* Python
  * Installed PyPI packages (global and venv)
  * Lockfiles: requirements.txt, poetry, Pipfile.lock, pdm.lock
* Ruby
  * Installed Gem packages
  * Lockfiles: Gemfile.lock (OSV)
* Rust
  * Cargo.lock (OSV)

## Container inventory

* Containerd container images that are running on host

## SBOM files

* SPDX SBOM descriptors
* CycloneDX SBOM descriptors

If you're a SCALIBR user and are interested in having it support new inventory types we're happy to accept contributions. See the docs on [how to add a new Extractor](/docs/new_extractor.md).
