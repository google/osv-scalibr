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
| ----------------- | ------------------------------ | -------------------------------------------- |
| Alpine            | APK                            | `os/apk`                                     |
| Chrome extensions |                                | `chrome/extensions`                          |
| COS               | cos-package-info.json          | `os/cos`                                     |
| DPKG              | e.g. Debian, Ubuntu            | `os/dpkg`                                    |
| Nix               |                                | `os/nix`                                     |
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
| Chocolatey        | Windows software               | `os/chocolatey`                              |
| Windows           | Build number                   | `windows/regosversion`                       |
| Windows           | Hotpatches                     | `windows/dismpatch`, `windows/regpatchlevel` |
| Windows           | Installed software             | `windows/ospackages`                         |

### Language packages

| Language   | Details                                   | Extractor Plugin(s)                  |
| ---------- | ----------------------------------------- | ------------------------------------ |
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
| Lua        | Luarocks modules                          | `lua/luarocks`                       |
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
|            | Gemfile.lock, gems.locked                 | `ruby/gemfilelock`                   |
| Rust       | Cargo.lock                                | `rust/cargolock`                     |
|            | Cargo.toml                                | `rust/cargotoml`                     |
|            | Rust binaries                             | `rust/cargoauditable`                |
| Swift      | Podfile.lock                              | `swift/podfilelock`                  |
|            | Package.resolved                          | `swift/packageresolved`              |
| Nim        | Nimble packages                           | `nim/nimble`                         |

### Language runtime managers

| runtime | Details        | Extractor Plugin(s) |
| ------- | -------------- | ------------------- |
| asdf    | .tool-versions | `runtime/asdf`      |
| mise    | mise.toml      | `runtime/mise`      |
| nvm     | .nvmrc         | `runtime/nvm`       |

### Secrets

| Type                                        | Extractor Plugin                       |
| ------------------------------------------- | -------------------------------------- |
| AWS access key                              | `secrets/awsaccesskey`                 |
| Amazon CodeCommit credentials               | `secrets/codecommitcredentials`        |
| Amazon CodeCatalyst credentials             | `secrets/codecatalystcredentials`      |
| Anthropic API key                           | `secrets/anthropicapikey`              |
| Azure Storage Account access key            | `secrets/azurestorageaccountaccesskey` |
| Azure Token                                 | `secrets/azuretoken`                   |
| Bitbucket                                   | `secrets/bitbucketcredentials`         |
| Composer Packagist credentials              | `secrets/composerpackagist`            |
| Crates.io API Token                         | `secrets/cratesioapitoken`             |
| Cursor API key                              | `secrets/cursorapikey`                 |
| DigitalOcean API key                        | `secrets/digitaloceanapikey`           |
| Docker hub PAT                              | `secrets/dockerhubpat`                 |
| Elastic Cloud API key                       | `secrets/elasticcloudapikey`           |
| GCP API key                                 | `secrets/gcpapikey`                    |
| GCP Express Mode API key                    | `secrets/gcpexpressmode`               |
| GCP service account key                     | `secrets/gcpsak`                       |
| GCP OAuth 2 Access Tokens                   | `secrets/gcpoauth2access`              |
| GCP OAuth 2 Client Credentials              | `secrets/gcpoauth2client`              |
| Google Cloud storage HMAC keys              | `secrets/gcshmackey`                   |
| Gitlab PAT                                  | `secrets/gitlabpat`                    |
| Grok xAI API key                            | `secrets/grokxaiapikey`                |
| Grok xAI Management key                     | `secrets/grokxaimanagementkey`         |
| Hashicorp Cloud Platform client credentials | `secrets/hcpclientcredentials`         |
| Hashicorp Cloud Platform access token       | `secrets/hcpaccesstoken`               |
| Hashicorp Vault token                       | `secrets/hashicorpvaulttoken`          |
| Hashicorp Vault AppRole token               | `secrets/hashicorpvaultapprole`        |
| Hugging Face API key                        | `secrets/huggingfaceapikey`            |
| MariaDB Credentials                         | `secrets/mariadb`                      |
| Mysql Mylogin                               | `secrets/mysqlmylogin`                 |
| 1Password Secret Key                        | `secrets/onepasswordsecretkey`         |
| 1Password Service Token                     | `secrets/onepasswordservicetoken`      |
| 1Password Recovery Code                     | `secrets/onepasswordrecoverycode`      |
| 1Password Connect Token                     | `secrets/onepasswordconnecttoken`      |
| OpenAI API key                              | `secrets/openai`                       |
| OpenRouter API key                          | `secrets/openrouter`                   |
| Packagist API Key                           | `secrets/packagist`                    |
| Packagist API Secret                        | `secrets/packagistsecret`              |
| Perplexity API key                          | `secrets/perplexityapikey`             |
| PyPI API Token                              | `secrets/pypiapitoken`                 |
| Postgres pgpass file                        | `secrets/pgpass`                       |
| Postman API key                             | `secrets/postmanapikey`                |
| Postman Collection token                    | `secrets/postmancollectiontoken`       |
| PEM/OpenSSH Private key                     | `secrets/privatekey`                   |
| RubyGems API key                            | `secrets/rubygemsapikey`               |
| Slack Application Level Token               | `secrets/slackappleveltoken`           |
| Slack Configuration Access Token            | `secrets/slackappconfigaccesstoken`    |
| Slack Configuration Refresh Token           | `secrets/slackappconfigrefreshtoken`   |
| Stripe Secret Key                           | `secrets/stripesecretkey`              |
| Stripe Restricted Key                       | `secrets/striperestrictedkey`          |
| Stripe Webhook Secret                       | `secrets/stripewebhooksecret`          |
| Tink keyset                                 | `secrets/tinkkeyset`                   |
| Paystack Secret Key                         | `secrets/paystacksecretkey`            |
| Vapid keys                                  | `secrets/vapidkey`                     |
| reCAPTCHA secret keys                       | `secrets/recaptchakey`                 |
| Generic JWT tokens                          | `secrets/jwttoken`                     |
| pyx user key v1                             | `secrets/pyxkeyv1`                     |
| pyx user key v2                             | `secrets/pyxkeyv2`                     |
| Telegram Bot API Token                      | `secrets/telegrambottoken`             |

### Container inventory

| Type                            | Extractor Plugin                                                                   |
| ------------------------------- | ---------------------------------------------------------------------------------- |
| Containerd container images     | `containers/containerd-runtime` (standalone), `containers/containerd` (filesystem) |
| Docker container images         | `containers/docker` (standalone)                                                   |
| Docker Compose container images | `containers/dockercomposeimage` (filesystem)                                       |
| K8s images                      | `containers/k8simage` (filesystem)                                                 |
| Podman container images         | `containers/podman` (filesystem)                                                   |

### SBOM files

| Type                       | Extractor Plugin |
| -------------------------- | ---------------- |
| SPDX SBOM descriptors      | `sbom/spdx`      |
| CycloneDX SBOM descriptors | `sbom/cdx`       |

### Misc

| Type                    | Extractor Plugin    |
| ----------------------- | ------------------- |
| Wordpress plugins       | `wordpress/plugins` |
| VSCode extensions       | `vscode/extensions` |
| Chrome extensions       | `chrome/extensions` |
| NetScaler installations | `netscaler`         |

### EmbeddedFS

| Type    | Details                                           | Extractor Plugin     |
| ------- | ------------------------------------------------- | -------------------- |
| archive | tar and tar.gz archives                           | `embeddedfs/archive` |
| ova     | Extracts .ova files                               | `embeddedfs/ova`     |
| vdi     | Supports Ext4, ExFAT, FAT32, and NTFS filesystems | `embeddedfs/vdi`     |
| vmdk    | Supports Ext4, ExFAT, FAT32, and NTFS filesystems | `embeddedfs/vmdk`    |

## Detectors

| Description                                                          | Plugin Name                              |
| -------------------------------------------------------------------- | ---------------------------------------- |
| Checks for overly permissive permissions on /etc/passwd.             | `cis/generic-linux/etcpasswdpermissions` |
| Finds vulns in Go binaries with reachability data using govulncheck. | `govulncheck/binary`                     |
| Checks if the Linux distribution is end-of-life.                     | `endoflife/linuxdistro`                  |
| Detects vulnerability CVE-2023-38408 in OpenSSH.                     | `cve/cve-2023-38408`                     |
| Detects vulnerability CVE-2022-33891 in Spark UI.                    | `cve/cve-2022-33891`                     |
| Detects vulnerability CVE-2020-16846 in Salt.                        | `cve/cve-2020-16846`                     |
| Detects vulnerability CVE-2023-6019 in Ray Dashboard.                | `cve/cve-2023-6019`                      |
| Detects vulnerability CVE-2020-11978 in Apache Airflow.              | `cve/cve-2020-11978`                     |
| Detects vulnerability CVE-2024-2912 in BentoML.                      | `cve/cve-2024-2912`                      |
| Detects vulnerability CVE-2025-7775 in NetScaler ADC / Gateway       | `cve/cve-2025-7775`                      |
| Checks for whether code-server has authentication enabled.           | `weakcredentials/codeserver`             |
| Checks for weak passwords in /etc/shadow.                            | `weakcredentials/etcshadow`              |
| Checks for default credentials in File Browser.                      | `weakcredentials/filebrowser`            |
| Checks for weak passwords for local Windows accounts.                | `weakcredentials/winlocal`               |

## Annotators

| Description                                                                       | Plugin Name                 |
| --------------------------------------------------------------------------------- | --------------------------- |
| Adds VEX statements for packages from cached directories                          | `vex/cachedir`              |
| Adds VEX statements for language packages already found by the APK OS extractor.  | `vex/os-duplicate/apk`      |
| Adds VEX statements for language packages already found by the COS OS extractor.  | `vex/os-duplicate/cos`      |
| Adds VEX statements for language packages already found by the DPKG OS extractor. | `vex/os-duplicate/dpkg`     |
| Adds VEX statements for language packages already found by the RPM OS extractor.  | `vex/os-duplicate/rpm`      |
| Adds VEX statements for DPKG findings where no executable is present              | `vex/no-executable/dpkg`    |
| Annotates NPM packages that were installed from NPM repositories                  | `misc/from-npm`             |
| Annotates DPKG packages with installation source                                  | `misc/dpkg-source`          |

## Enrichers

| Description                                                                | Plugin Name                         |
| -------------------------------------------------------------------------- | ----------------------------------- |
| Extracts details about the base image a software package was added in      | `baseimage`                         |
| Filters findings that have VEX statements.                                 | `vex/filter`                        |
| Validates secrets, e.g. checking if a GCP service account key is active.   | `secrets/velesvalidate`             |
| Finds vulns in Go source with reachability data using govulncheck. Requires a vulnmatch enricher to be enabled. | `reachability/go/source`            |
| Performs reachability analysis for Java code.                              | `reachability/java`                 |
| Performs reachability analysis for Rust code. (Linux-only)                 | `reachability/rust`                 |
| Resolves transitive dependencies for Python pip packages.                  | `transitivedependency/requirements` |
| Queries the OSV.dev API to find vulnerabilities in the inventory packages. | `vulnmatch/osvdev`                  |
| Adds license data to software packages                                     | `license/depsdev`                   |
| Checks if package versions are deprecated (e.g. yanked, unpublished).      | `packagedeprecation/depsdev`        |
