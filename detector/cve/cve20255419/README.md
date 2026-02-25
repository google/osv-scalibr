# CVE-2025-5419 Detector

Detects installations of Chromium-based applications affected by
[CVE-2025-5419](https://nvd.nist.gov/vuln/detail/CVE-2025-5419) — an
out-of-bounds read and write in V8 that allows a remote attacker to
exploit heap corruption via a crafted HTML page.

- **CVSS 3.1**: 8.8 HIGH (`AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H`)
- **CISA KEV**: added 2025-06-05, remediation deadline 2025-06-26

## Fixed Versions

| Product | Fixed version | Notes |
|---|---|---|
| Google Chrome / Chromium | **137.0.7151.68** | Stable channel |
| Microsoft Edge | **137.0.3296.62** | Stable channel |
| Microsoft Edge | **136.0.3240.115** | Extended Stable channel |
| Electron 34.x | **34.5.8** | Backport; embeds Chromium 132.0.6834.210 |
| Electron 35.x | **35.5.1** | Backport; embeds Chromium 134.0.6998.205 |
| Electron 36.x | **36.4.0** | Backport; embeds Chromium 136.0.7103.149 |
| Electron 37.x | **37.0.0-beta.3** | Backport; embeds Chromium 138.0.7190.0 |
| Electron < 34 | — | EOL; no in-branch fix available |

## Required Extractor

This detector depends on the `misc/chromiumapps` extractor, which must
run first to populate the package index with Chromium-family packages.

## Detection Decision Tree

The detector evaluates each package through the following logic:

```mermaid
flowchart TD
    Start([Package from index]) --> GetName[Read pkgName]
    GetName --> Switch{pkgName?}

    Switch -->|"google-chrome\nchromium"| ChromeCheck["version < 137.0.7151.68?"]
    ChromeCheck -->|yes| VulnChrome["VULNERABLE\nfixed: 137.0.7151.68"]
    ChromeCheck -->|no| SafeChrome([NOT VULNERABLE])

    Switch -->|microsoft-edge| EdgeMajor{"major version?"}
    EdgeMajor -->|"<= 136"| EdgeLow["version < 136.0.3240.115?"]
    EdgeLow -->|yes| VulnEdge136["VULNERABLE\nfixed: 136.0.3240.115"]
    EdgeLow -->|no| SafeEdge136([NOT VULNERABLE])
    EdgeMajor -->|"== 137"| EdgeHigh["version < 137.0.3296.62?"]
    EdgeHigh -->|yes| VulnEdge137["VULNERABLE\nfixed: 137.0.3296.62"]
    EdgeHigh -->|no| SafeEdge137([NOT VULNERABLE])
    EdgeMajor -->|">= 138"| SafeEdgeNew([NOT VULNERABLE])

    Switch -->|electron| HasElectronVer{"Metadata.\nElectronVersion\navailable?"}

    HasElectronVer -->|yes| ElectronMajor{"Electron\nmajor?"}
    ElectronMajor -->|"< 34"| VulnElectronEOL["VULNERABLE\nEOL branch — no\nin-branch fix;\nmust upgrade to\nElectron 34+"]
    ElectronMajor -->|"== 34"| Elec34["< 34.5.8?"]
    Elec34 -->|yes| VulnElec34([VULNERABLE])
    Elec34 -->|no| SafeElec34([NOT VULNERABLE])
    ElectronMajor -->|"== 35"| Elec35["< 35.5.1?"]
    Elec35 -->|yes| VulnElec35([VULNERABLE])
    Elec35 -->|no| SafeElec35([NOT VULNERABLE])
    ElectronMajor -->|"== 36"| Elec36["< 36.4.0?"]
    Elec36 -->|yes| VulnElec36([VULNERABLE])
    Elec36 -->|no| SafeElec36([NOT VULNERABLE])
    ElectronMajor -->|"== 37"| Elec37["< 37.0.0-beta.3?\n(semver)"]
    Elec37 -->|yes| VulnElec37([VULNERABLE])
    Elec37 -->|no| SafeElec37([NOT VULNERABLE])
    ElectronMajor -->|">= 38\nor unknown"| FallbackCore["Fall back to\nChromiumVersion path"]

    HasElectronVer -->|no| HasChromeCore{"Metadata.\nChromiumVersion\navailable?"}
    HasChromeCore -->|no| Skip([SKIP — cannot evaluate])
    HasChromeCore -->|yes| FallbackCore

    FallbackCore --> BackportFloor["ChromiumVersion\n< 132.0.6834.210?\n(Electron backport floor)"]
    BackportFloor -->|yes| VulnFloor["VULNERABLE\nfixed: 132.0.6834.210\n(earliest Electron backport)"]
    BackportFloor -->|no| CoreCheck["ChromiumVersion\n< 137.0.7151.68?"]
    CoreCheck -->|yes| VulnCore["VULNERABLE\nfixed: 137.0.7151.68"]
    CoreCheck -->|no| SafeCore([NOT VULNERABLE])

    Switch -->|other| SkipOther([SKIP])
```

### Key design notes

**Standalone Chrome vs Electron-embedded Chromium**

Standalone Chrome and Chromium packages are always evaluated directly
against `137.0.7151.68`. The Electron backport floor (`132.0.6834.210`)
only applies to Electron's *embedded* Chromium core: Electron 34.5.8
shipped a patched Chromium 132, but no equivalent patch was released for
the standalone Chrome 132 channel.

**Electron version comparison**

Electron versions are compared using semver semantics via
`golang.org/x/mod/semver`. Four-part numeric versions such as `36.4.0.1`
have their fourth segment stripped before comparison (`36.4.0`), so they
are treated as equal to — rather than greater than — the three-part
release. Pre-release tags (e.g. `37.0.0-beta.3`) are handled correctly:
any stable release is considered newer than a beta of the same version.

**EOL Electron branches (major < 34)**

Electron branches below major 34 received no backport fix. These
installations are flagged as vulnerable. The finding's `extra` field
explicitly notes that no in-branch fix exists and users must upgrade to
Electron 34 or later.
