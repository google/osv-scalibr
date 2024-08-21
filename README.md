# OSV-SCALIBR

**Note:** The code in this repo is subject to change in the near future as we're merging SCALIBR with [OSV-scanner](https://github.com/google/osv-scanner) to provide a single tool that unifies the two scanners' extraction and vuln scanning capabilities.

SCALIBR (Software Composition Analysis Library) is an extensible file system scanner used to extract software inventory data (e.g. installed language packages) and detect vulnerabilities.

The scanner can either be used as a standalone binary to scan the local machine or as a library with a custom wrapper to perform scans on e.g. container images or remote hosts. It comes with built-in plugins for inventory extraction and vulnerability detection and it also allows users to run their custom plugins.

See [here](docs/supported_inventory_types.md) for the list of currently supported software inventory types.

## Prerequisites

To build SCALIBR, you'll need to have `go` installed. Follow https://go.dev/doc/install.

## How to use

### As a standalone binary

1. `go install github.com/google/osv-scalibr/binary`
1. `scalibr --result=result.textproto`

See the [result proto definition](/binary/proto/scan_result.proto) for details about the scan result format.

Run `scalibr --help` for a list of additional CLI args.

### As a library:
1. Import `github.com/google/osv-scalibr` into your Go project
1. Create a new [scalibr.ScanConfig](/scalibr.go#L36) struct, configure the extraction and detection plugins to run
1. Call `scalibr.New().Scan()` with the config
1. Parse the returned [scalibr.ScanResults](/scalibr.go#L50)

See below for an example code snippet.

### On a container image

See the [run_scalibr_on_image.sh](/run_scalibr_on_image.sh) script for an example of how to run SCALIBR on container images.

### SPDX generation

SCALIBR supports generating the result of inventory extraction as an SPDX v2.3 file in json, yaml or tag-value format. Example usage:

```
scalibr -o spdx23-json=result.spdx.json
```

Some fields in the generated SPDX can be overwritten:

```
scalibr -spdx-document-name="Custom name" --spdx-document-namespace="Custom-namespace" --spdx-creators=Organization:Google -o spdx23-json=result.spdx.json
```

## Running built-in plugins

### With the standalone binary
The binary runs SCALIBR's "recommended" internal plugins by default. You can enable more plugins with the `--extractors=` and `--detectors=` flags. See the the definition files for a list of all built-in plugins and their CLI flags ([extractors (fs)](/extractor/filesystem/list/list.go#L26), [detectors](/detector/list/list.go#L26)).

### With the library
A collection of all built-in plugin modules can be found in the definition files ([extractors](/extractor/filesystem/list/list.go#L26), [detectors](/detector/list/list.go#L26)). To enable them, just import the module and add the appropriate plugins to the scan config, e.g.

```
import (
  scalibr "github.com/google/osv-scalibr"
  el "github.com/google/osv-scalibr/extractor/filesystem/list"
  dl "github.com/google/osv-scalibr/detector/list"
)
cfg := &scalibr.ScanConfig{
  Root:                 "/",
  FilesystemExtractors: el.Python,
  Detectors:            dl.CIS,
}
results := scalibr.New().Scan(context.Background(), cfg)
```

## Creating + running custom plugins
Custom plugins can only be run when using SCALIBR as a library.

1. Create an implementation of the SCALIBR [Extractor](/extractor/filesystem/extractor.go#L30) or [Detector](/detector/detector.go#L28) interface.
2. Add the newly created struct to the scan config and run the scan, e.g.

```
import (
  "github.com/google/osv-scalibr/extractor/filesystem"
  scalibr "github.com/google/osv-scalibr"
)
cfg := &scalibr.ScanConfig{
  Root:                 "/",
  FilesystemExtractors: []extractor.Extractor{&myExtractor{}},
}
results := scalibr.New().Scan(context.Background(), cfg)
```

### A note on cross-platform

SCALIBR is compatible with Linux and has experimental support for Windows and
Mac. When a new plugin is implemented for SCALIBR, we need to ensure that it
will not break other platforms. Our runners will generally catch compatibility
issue, but to ensure everything is easy when implementing a plugin, here are a
few recommendations to keep in mind:

*   Ensure you work with file paths using the `filepath` library. For example,
    avoid using `/my/path` but prefer `filepath.Join('my', 'path')` instead.
*   If the plugin can only support one system (e.g. a windows-specific
    detector), the layout will generally be to have two versions of the file:
    *   `file_system.go`: where `system` is the targeted system (e.g.
        `file_windows.go`) that contains the code specific to the target system.
        It must also contain the adequate go build constraint.
    *   `file_dummy.go`: contains the code for every other system. It generally
        does nothing and just ensures that the code compiles on that system;
*   Because of the way our internal automation works, we generally require unit
    tests to be defined for every platform and be filtered out dynamically if
    not compatible. In other words, a test should be filtered in/out using
    `if runtime.GOOS` rather than a `//go:build` constraint. Here is an
    [example](https://github.com/google/osv-scalibr/commit/7a87679f5c688e7bac4527d29c1823597a52bb40#diff-72efad005e0fbfe34c60e496dfb55ec15fc50f4b12be0934f08a3acaf7733616L79).

## Custom logging
You can make the SCALIBR library log using your own custom logger by passing an implementation of the [`log.Logger`](/log/log.go#L22) interface to `log.SetLogger()`:

```
import (
  customlog "path/to/custom/log"
  "github.com/google/osv-scalibr/log"
  scalibr "github.com/google/osv-scalibr"
)
cfg := &scalibr.ScanConfig{ScanRoot: "/"}
log.SetLogger(&customlog.Logger{})
results := scalibr.New().Scan(context.Background(), cfg)
log.Info(results)
```

## Contributing
Read how to [contribute to SCALIBR](CONTRIBUTING.md).

To build and test your local changes, run `make` and `make test`. A local `scalibr` binary will be generated in the repo base.

Some of your code contributions might require regenerating protos. This can
happen when, say, you want to contribute a new inventory type. For such cases,
you'll need install a few dependencies

* `protoc`: Install the appropriate [precompiled protoc binary](https://grpc.io/docs/protoc-installation/#install-pre-compiled-binaries-any-os).
  * For Mac, you can also [install via HomeBrew](https://grpc.io/docs/protoc-installation/#install-using-a-package-manager).
* `protoc-gen-go`: Run `go install google.golang.org/protobuf/cmd/protoc-gen-go`

and then run `make protos` or `./build_protos.sh`.

## Disclaimers
SCALIBR is not an official Google product.
