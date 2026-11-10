# Runtime Extractors

Runtime extractors live under `extractor/filesystem/runtime/` rather than
`extractor/filesystem/language/` because runtimes and standalone CLI tools
(such as `nodejs`, `python`, `golang`, `terraform`, and `runc`) are installed
executables rather than libraries from a language package registry:

- They publish advisories outside language package ecosystems (for example,
  `nodejs` is not hosted on `npm`, and CPython is not hosted on PyPI).
- Multi-runtime managers (`asdf`, `mise`) configure language runtimes alongside
  infrastructure and container tools in the same file.

## Directory Layout

| Pattern | Plugin Name | Scope | Examples |
| --- | --- | --- | --- |
| `runtime/<manager>` | `runtime/<manager>` | Managers that install multiple runtime types | `runtime/asdf`, `runtime/mise` |
| `runtime/<runtime>/<manager>` | `runtime/<manager>` | Managers specific to a single runtime | `runtime/nodejs/nvm`, `runtime/nodejs/nodeversion` |

## Inventory and PURL Convention

Runtime extractors return
[`extractor.Package`](/extractor/extractor.go)
entries with `PURLType: purl.TypeGeneric`:

```text
pkg:generic/<runtime_name>@<runtime_version>
```

Examples:

```text
pkg:generic/nodejs@20.12.2
pkg:generic/terraform@1.6.0
pkg:generic/runc@1.1.12
```

Using `pkg:generic` instead of manager-specific types (`pkg:asdf`, `pkg:mise`)
or language/plugin types (`pkg:npm`, `pkg:terraform`) keeps runtime inventory
consistent:

- Multiple extractors (`runtime/asdf`, `runtime/mise`, `runtime/nvm`, and
  `runtime/nodeversion`) emit identical PURLs for the same runtime version.
- Ecosystem PURL types (such as `pkg:npm` or proposed
  [`pkg:terraform`](https://github.com/package-url/purl-spec/pull/498))
  represent packages, modules, or plugins rather than the core runtime binary.

## Normalization Rules

- Unwrap runtime backend prefixes (`core:`, `asdf:`, `vfox:`), skip non-runtime
  package backends (for example, `npm:`, `cargo:`), and normalize short tool
  aliases in multi-runtime configs to canonical runtime names (for example,
  `node` -> `nodejs`, `go` -> `golang`, `py` -> `python`; see
  [`asdf.go`](/extractor/filesystem/runtime/asdf/asdf.go)
  and
  [`mise.go`](/extractor/filesystem/runtime/mise/mise.go)),
  preserving raw `ToolName` and `ToolVersion` strings in manager metadata.
- Strip leading `v` prefixes on numeric versions (for example, `v20.12.2` ->
  `20.12.2`).
- Skip symbolic, range, or local/VCS specifiers that do not pin a concrete
  version (for example, `system`, `latest`, `lts`, `nightly`, `path:...`, or
  `ref:...`).
