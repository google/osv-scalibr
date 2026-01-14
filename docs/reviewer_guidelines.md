# Scalibr Plugin Review Process

This guide explains the standards and expectations for the Scalibr project. Before a pull request (PR) is merged, it should meet all the requirements outlined in the checklists below.

## 1. General Guidelines

These guidelines apply to all contributions.

- [ ] **Follow the Style Guide**: Code must conform to the [Scalibr Style Guide](https://github.com/google/osv-scalibr/blob/main/docs/style_guide.md).

- [ ] **Minimize Dependencies**: New dependencies should be avoided unless necessary. If a library is imported to use only few "simple" functions, re-implementing the logic manually or copying the specific function is preferred.

- [ ] **Check the license of new dependencies**: Some of the forbidden licenses are: AGPL (Affero GPL), OSL, SSPL, Cryptographic Autonomy License (CAL), CPAL, CPOL, European Union Public Licence (EUPL), SISSL, Watcom-1.0. When in doubt, check with the Scalibr team.

- [ ] **High Code Quality & Testing**: While 100% test coverage is not strictly enforced, tests must be meaningful and cover **every edge case** present in the code logic.

- [ ] **Linting**: Code must be properly linted using the provided [.golangci.yaml](https://github.com/google/osv-scalibr/blob/main/.golangci.yaml) configuration.

- [ ] **Cross-Platform Compatibility**:
  - Tests must pass on all operating systems, platform-specific tests must be explicitly skipped on unsupported OSes using `t.Skip`.
  - Outside of tests, if a plugin doesn't compile for an OS because an import or struct doesn't exist for that OS build target, it should be removed using `go:build` tags ([example](https://github.com/google/osv-scalibr/blob/4f04caa1e9b8c547520759ecf14596877df0d07b/extractor/filesystem/os/rpm/rpm.go#L15))

## 2. Plugin Development

This section describes requirements that are specific to developing plugins.

### Core Requirements

- [ ] **Registration**: New plugins must be registered in the respective `list.go` file (e.g., [annotator/list/list.go](https://github.com/google/osv-scalibr/blob/main/annotator/list/list.go)).
- [ ] **Protobuf Definition**: Plugin results must be added to the [scan_result.proto](https://github.com/google/osv-scalibr/tree/main/binary/proto/scan_result.proto) file.
- [ ] **Data Conversion**: Conversion logic between Go structs and `.proto` definitions (and vice versa) is required.

### Specific Plugin Guidelines

#### Annotators

_No specific additional requirements._

#### Detectors

- [ ] **Return the same finding every time**: The returned findings (either GenericFinding or PackageVulns) should be the same every time, with the exception of the [Target](https://github.com/google/osv-scalibr/blob/4f04caa1e9b8c547520759ecf14596877df0d07b/inventory/finding.go#L59) / [DatabaseSpecific](https://github.com/google/osv-scalibr/blob/4f04caa1e9b8c547520759ecf14596877df0d07b/inventory/finding.go#L59) fields where instance-specific data can go (e.g. the specific config setting found that was vulnerable)
- [ ] **Documentation**: The detected vulnerability type must be added to [supported_inventory_types.md](https://github.com/google/osv-scalibr/tree/main/docs/supported_inventory_types.md) file.

#### Enrichers

- [ ] **Side-Effect Free**: API calls made by Enrichers should be as side-effect-free as possible.

#### Extractors

- [ ] **Performance Optimization**: The `FileRequired` method is a "hot path" called on every scanned file and must be highly optimized. For example: strings.HasPrefix/HasSuffix/Contains matches are okay, regexps are not.
- [ ] **Memory Footprint**: The `Extract` method must use memory efficiently. Loading entire files into memory is to be avoided; buffering is preferred (e.g., avoid `io.ReadAll` if possible).
- [ ] **Use helper library in tests**: Tests should use the [simplefileapi](https://github.com/google/osv-scalibr/blob/4f04caa1e9b8c547520759ecf14596877df0d07b/extractor/filesystem/language/golang/gomod/gomod_test.go#L64) and [extracttest](https://github.com/google/osv-scalibr/blob/4f04caa1e9b8c547520759ecf14596877df0d07b/extractor/filesystem/language/golang/gomod/gomod_test.go#L404) helper libs whenever possible.
- [ ] **Documentation**: The extracted inventory type must be added to the [supported_inventory_types.md](https://github.com/google/osv-scalibr/tree/main/docs/supported_inventory_types.md) file.

---

## 3. Veles Secrets

The `veles` package is a standalone library. Scalibr utilizes it by wrapping secret detectors as `filesystem.Extractor`. (See [Veles README](https://github.com/google/osv-scalibr/tree/main/veles/README.md)).

- [ ] **Package Isolation**: The `veles` package is standalone. Detectors within this package **must not** import packages from outside the `veles` folder.

- [ ] **Zero False Positives**: Most secrets should be detectable with a near-zero false positive rate. Use bounded queries (e.g., `\b[a-Z]\b`) by default. If a specific secret type requires logic that allows false positives, justification must be provided in the PR.

- [ ] **Validate when possible**: Detectors must be accompanied by a validator whenever secret validation is feasible.

- [ ] **Side-Effect Free Validation**: Validators must be as **side-effect-free** as possible.

- [ ] **Documentation**: The detected secret type must be added to the [supported_inventory_types.md](https://github.com/google/osv-scalibr/tree/main/docs/supported_inventory_types.md) file.

- [ ] **Common utilities**: When possible use common utilities like [simpletoken.Detector](https://github.com/doyensec/osv-scalibr/blob/cf20290d76242f45365a0285e09dd6023b634bc5/veles/secrets/openai/detector.go#L41) for detectors and [simplevalidate.Validator](https://github.com/doyensec/osv-scalibr/blob/cf20290d76242f45365a0285e09dd6023b634bc5/veles/secrets/github/oauth_validator.go#L26C10-L26C24)
