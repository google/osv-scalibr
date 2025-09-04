# Supported Plugins

OSV-SCALIBR uses a plugin-based system for its scanning and vulnerability
matching capabilities. During each run, a
series of plugins are enabled to perform specific tasks.

Plugins are grouped into the following categories:

- **Extractors**: Identify software packages, dependencies, and other inventory.
- **Detectors**: Detect security findings, such as misconfigurations or
                 specific vulnerabilities.
- **Enrichers**: Augment inventory with additional data from external sources.
- **Annotators**: Add contextual information to the inventory.

> [!TIP]
> Learn how to contribute new plugins by reading the documentation
> for [new extractors](/docs/new_extractor.md.md),
> [new detectors](/docs/new_detector),
> and [new enrichers](/docs/new_enricher.md).

The following sections list all available plugins.

## Extractors

OSV-SCALIBR extractors support a wide variety of OS and language package
managers. Some reuse extraction logic from Google's
[OSV-Scanner](https://github.com/google/osv-scanner).

If you're an OSV-SCALIBR user and are interested in having it support new
inventory types we're happy to accept contributions.
See the docs on [how to add a new Extractor](/docs/new_extractor.md).

### OS packages

| Inventory Type    | Details                        | Extractor Plugin                             |
|-------------------|--------------------------------|----------------------------------------------|
| Alpine            | APK                            | `os/apk`                                     |
| Chrome extensions |                                | `chrome/extensions`                          |
| COS               | cos-package-info.json          | `os/cos`                                     |
| DPKG              | e.g. Debian, Ubuntu            | `os/dpkg`                                    |
| NIX               |                                | `os/nix`                                     |
| OPKG              | e.g. OpenWrt                   | `os/dpkg`                                    |
| RPM               | e.g. RHEL, CentOS, Rocky Linux | `os/rpm`                                     |
| Zypper            | e.g. openSUSE                  | `os/rpm`                                     |
| Pacman            | e.g. Arch Linux                | `os/pacman`                                  |
| Kernel modules    | .ko                            | `os/kernel/module`                           |
| Kernel archives   | vmlinuz                        | `os/kernel/vmlinuz`                          |
| Portage           | e.g. Gentoo Linux              | `os/portage`                                 |
| SNAP              |                                | `os/snap`                                    |
| Flatpak           |                                | `os/flatpak`                                 |
| Homebrew          | OS X                           | `os/homebrew`                                |
| MacPorts          | OS X                           | `os/macports`                                |
| OS X Applications | OS X                           | `os/macapps`                                 |
| Windows           | Build number                   | `windows/regosversion`                       |
| Windows           | Hotpatches                     | `windows/dismpatch`, `windows/regpatchlevel` |
| Windows           | Installed software             | `windows/ospackages`                         |

### Language packages

| Language   | Details                                   | Extractor Plugin(s)                  |
|------------|-------------------------------------------|--------------------------------------|
| .NET       | packages.lock.json                        | `dotnet/packageslockjson`            |
|            | packages.config                           | `dotnet/packagesconfig`              |
|            | deps.json                                 | `dotnet/depsjson`                    |
|            | portable executables                      | `dotnet/pe`                          |
| C++        | Conan packages                            | `cpp/conanlock`                      |
| Dart       | pubspec.lock                              | `dart/pubspec`                       |
| Erlang     | mix.lock                                  | `erlang/mixlock`                     |
| Elixir     | mix.lock                                  | `elixir/mixlock`                     |
| Go         | Go binaries                               | `go/binary`                          |
|            | go.mod (OSV)                              | `go/gomod`                           |
| Haskell    | stack.yaml.lock                           | `haskell/stacklock`                  |
|            | cabal.project.freeze                      | `haskell/cabal`                      |
| Java       | Java archives                             | `java/archive`                       |
|            | pom.xml                                   | `java/pomxml`, `java/pomxmlnet`      |
|            | gradle.lockfile                           | `java/gradlelockfile`                |
|            | verification-metadata.xml                 | `java/gradleverificationmetadataxml` |
| Javascript | Installed NPM packages (package.json)     | `javascript/packagejson`             |
|            | package-lock.json, npm-shrinkwrap.json    | `javascript/packagelockjson`         |
|            | yarn.lock                                 | `javascript/yarnlock`                |
|            | pnpm-lock.yaml                            | `javascript/pnpmlock`                |
|            | bun.lock                                  | `javascript/bunlock`                 |
| ObjectiveC | Podfile.lock                              | `swift/podfilelock`                  |
| PHP        | Composer                                  | `php/composerlock`                   |
| Python     | Installed PyPI packages (global and venv) | `python/wheelegg`                    |
|            | requirements.txt                          | `python/requirements`                |
|            | poetry.lock                               | `python/poetrylock`                  |
|            | Pipfile.lock                              | `python/pipfilelock`                 |
|            | pdm.lock                                  | `python/pdmlock`                     |
|            | Conda packages                            | `python/condameta`                   |
|            | setup.py                                  | `python/setup`                       |
|            | uv.lock                                   | `python/uvlock`                      |
| R          | renv.lock                                 | `r/renvlock`                         |
| Ruby       | Installed Gem packages                    | `ruby/gemspec`                       |
|            | Gemfile.lock (OSV)                        | `ruby/gemfilelock`                   |
| Rust       | Cargo.lock                                | `rust/cargolock`                     |
|            | Cargo.toml                                | `rust/cargotoml`                     |
|            | Rust binaries                             | `rust/cargoauditable`                |
| Swift      | Podfile.lock                              | `swift/podfilelock`                  |
|            | Package.resolved                          | `swift/packageresolved`              |

### Container inventory

| Type                        | Extractor Plugin                                                                   |
|-----------------------------|------------------------------------------------------------------------------------|
| Containerd container images | `containers/containerd-runtime` (standalone), `containers/containerd` (filesystem) |
| Docker container images     | `containers/docker` (standalone)                                                   |
| Podman container images     | `containers/podman` (filesystem)                                                   |

### SBOM files

| Type                       | Extractor Plugin |
|----------------------------|------------------|
| SPDX SBOM descriptors      | `sbom/spdx`      |
| CycloneDX SBOM descriptors | `sbom/cdx`       |

### Misc

| Type              | Extractor Plugin    |
|-------------------|---------------------|
| Wordpress plugins | `wordpress/plugins` |
| VSCode extensions | `vscode/extensions` |
| Chrome extensions | `chrome/extensions` |

### Embeddedfs

| Type | Extractor Plugin |
|------|------------------|
| ova  | `embeddedfs/ova` |

## Detectors

| Description                                                          | Plugin Name                              |
|----------------------------------------------------------------------|------------------------------------------|
| Checks for overly permissive permissions on /etc/passwd.             | `cis/generic-linux/etcpasswdpermissions` |
| Finds vulns in Go binaries with reachability data using govunlcheck. | `govulncheck/binary`                     |
| Checks if the Linux distribution is end-of-life.                     | `endoflife/linuxdistro`                  |
| Detects vulnerability CVE-2023-38408 in OpenSSH.                     | `cve/cve-2023-38408`                     |
| Detects vulnerability CVE-2022-33891 in Spark UI.                    | `cve/cve-2022-33891`                     |
| Detects vulnerability CVE-2020-16846 in Salt.                        | `cve/cve-2020-16846`                     |
| Detects vulnerability CVE-2023-6019 in Ray Dashboard.                | `cve/cve-2023-6019`                      |
| Detects vulnerability CVE-2020-11978 in Apache Airflow.              | `cve/cve-2020-11978`                     |
| Detects vulnerability CVE-2024-2912 in BentoML.                      | `cve/cve-2024-2912`                      |
| Checks for whether code-server has authentication enabled.           | `weakcredentials/codeserver`             |
| Checks for weak passwords in /etc/shadow.                            | `weakcredentials/etcshadow`              |
| Checks for default credentials in File Browser.                      | `weakcredentials/filebrowser`            |
| Checks for weak passwords for local Windows accounts.                | `weakcredentials/winlocal`               |

## Annotators

| Description                                                                       | Plugin Name              |
|-----------------------------------------------------------------------------------|--------------------------|
| Adds VEX statements for packages from cached directories                          | `vex/cachedir`           |
| Adds VEX statements for language packages already found by the APK OS extractor.  | `vex/os-duplicate/apk`   |
| Adds VEX statements for language packages already found by the COS OS extractor.  | `vex/os-duplicate/cos`   |
| Adds VEX statements for language packages already found by the DPKG OS extractor. | `vex/os-duplicate/dpkg`  |
| Adds VEX statements for language packages already found by the RPM OS extractor.  | `vex/os-duplicate/rpm`   |
| Adds VEX statements for DPKG findings where no executable is present              | `vex/no-executable/dpkg` |
| Annotates NPM packages that were installed from NPM repositories                  | `misc/from-npm`          |

## Enrichers

| Description                                                                | Plugin Name                         |
|----------------------------------------------------------------------------|-------------------------------------|
| Extracts details about the base image a software package was added in      | `baseimage`                         |
| Filters findings that have VEX statements.                                 | `vex/filter`                        |
| Validates secrets, e.g. checking if a GCP service account key is active.   | `secrets/velesvalidate`             |
| Performs reachability analysis for Java code.                              | `reachability/java`                 |
| Resolves transitive dependencies for Python pip packages.                  | `transitivedependency/requirements` |
