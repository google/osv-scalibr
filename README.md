# OSV-SCALIBR

[![Go Reference](https://pkg.go.dev/badge/github.com/google/osv-scalibr.svg)](https://pkg.go.dev/github.com/google/osv-scalibr)

OSV-SCALIBR (Software Composition Analysis Library) is an extensible library
providing:

- File system scanner used to extract software inventory data (e.g.
installed language packages) and detect known vulnerabilities or generate SBOMs.
See the
[list of currently supported software inventory types](docs/supported_inventory_types.md).
- Container analysis functionality (e.g. layer-based extraction)
- Guided Remediation (generating upgrade patches for transitive vulnerabilities)
- And more!

This can be used as a library with a custom wrapper to perform scans on e.g.
container images (only linux-based currently) or remote hosts, or via the
[OSV-Scanner CLI](https://github.com/google/osv-scanner). It comes with built-in
plugins for inventory extraction and vulnerability detection and it also allows
users to run their custom plugins.

## Prerequisites

To build OSV-SCALIBR, you'll need to have `go` installed. Follow
https://go.dev/doc/install.

## How to use

### Via the OSV-Scanner CLI

If your use case is known vulnerability scanning and extraction in a CLI
context, check out the
[OSV-Scanner usage guide](https://google.github.io/osv-scanner/usage/).

**Note:** Not all OSV-SCALIBR functionality is available via OSV-Scanner yet.
Check out [this migration guide](https://google.github.io/osv-scanner/migrating-from-scalibr.html)
for more information.

### Via the OSV-SCALIBR wrapper binary

1. `go install github.com/google/osv-scalibr/binary/scalibr@latest`
1. `scalibr --result=result.textproto`

See the [result proto definition](/binary/proto/scan_result.proto) for details
about the scan result format.

Run `scalibr --help` for a list of additional CLI args.

### As a library:

1.  Import `github.com/google/osv-scalibr` into your Go project
1.  Create a new [scalibr.ScanConfig](/scalibr.go#L36) struct, configure the
    extraction and detection plugins to run
1.  Call `scalibr.New().Scan()` with the config
1.  Parse the returned [scalibr.ScanResults](/scalibr.go#L50)

See below for an example code snippet.

### On a container image

Add the `--remote-image` flag to scan a remote container image. Example:

```
scalibr --result=result.textproto --remote-image=alpine@sha256:0a4eaa0eecf5f8c050e5bba433f58c052be7587ee8af3e8b3910ef9ab5fbe9f5
```

Or the `--image-tarball` flag to scan a locally saved image tarball like ones
produced with `docker save my-image > my-image.tar`. Example:

```
scalibr --result=result.textproto --image-tarball=my-image.tar
```

Note: As mentioned previously only linux-based container images are supported
currently. Follow issue [#953](https://github.com/google/osv-scalibr/issues/953)
for tracking Windows image container scanning support.

### SPDX generation

OSV-SCALIBR supports generating the result of inventory extraction as an SPDX
v2.3 file in json, yaml or tag-value format. Example usage:

```
scalibr -o spdx23-json=result.spdx.json
```

Some fields in the generated SPDX can be overwritten:

```
scalibr -spdx-document-name="Custom name" --spdx-document-namespace="Custom-namespace" --spdx-creators=Organization:Google -o spdx23-json=result.spdx.json
```

## Running built-in plugins

### With the standalone binary

The binary runs SCALIBR's "recommended" internal plugins by default. You can
enable more plugins with the `--plugins=` flags. See the
definition files for a list of all built-in plugins and their CLI flags
([extractors (fs)](/extractor/filesystem/list/list.go),
[extractors (standalone)](/extractor/filesystem/list/list.go),
[detectors](/detector/list/list.go),
[annotators](/annotator/list/list.go),
[enrichers](/enricher/enricherlist/list.go)).

### With the library

A collection of all built-in plugin modules can be found in the definition files
([extractors (fs)](/extractor/filesystem/list/list.go),
[extractors (standalone)](/extractor/filesystem/list/list.go),
[detectors](/detector/list/list.go),
[annotators](/annotator/list/list.go),
[enrichers](/enricher/enricherlist/list.go)).
To enable them, just import plugins/list and add the appropriate plugin names
to the scan config, e.g.
```
import (
  "context"
  scalibr "github.com/google/osv-scalibr"
  pl "github.com/google/osv-scalibr/plugins/list"
  scalibrfs "github.com/google/osv-scalibr/fs"
)
plugins, _ := pl.FromNames([]string{"os", "cis", "vex"})
cfg := &scalibr.ScanConfig{
  ScanRoots: scalibrfs.RealFSScanRoots("/"),
  Plugins:   plugins,
}
results := scalibr.New().Scan(context.Background(), cfg)
```

You can also specify your scanning host's capabilities to only enable plugins
whose requirements are satisfied (e.g. network access, OS-specific plugins):

```
import (
  ...
  "github.com/google/osv-scalibr/plugin"
)
capab := &plugin.Capabilities{
  OS:            plugin.OSLinux,
  Network:       plugin.NetworkOnline,
  DirectFS:      true,
  RunningSystem: true,
}
...
cfg := &scalibr.ScanConfig{
  ScanRoots: scalibrfs.RealFSScanRoots("/"),
  Plugins:   plugin.FilterByCapabilities(plugins, capab),
}
...
```

## Creating + running custom plugins

Custom plugins can only be run when using OSV-SCALIBR as a library.

1.  Create an implementation of the OSV-SCALIBR
    [Extractor](/extractor/filesystem/extractor.go#L30) or
    [Detector](/detector/detector.go#L28) interface.
2.  Add the newly created struct to the scan config and run the scan, e.g.

```
import (
  "github.com/google/osv-scalibr/plugin"
  scalibr "github.com/google/osv-scalibr"
)
cfg := &scalibr.ScanConfig{
  Root:                 "/",
  Plugins: []plugin.Plugin{&myExtractor{}},
}
results := scalibr.New().Scan(context.Background(), cfg)
```

### A note on cross-platform

OSV-SCALIBR is compatible with Linux and has experimental support for Windows
and Mac. When a new plugin is implemented for OSV-SCALIBR, we need to ensure
that it will not break other platforms. Our runners will generally catch
compatibility issues, but to ensure everything is easy when implementing a
plugin, here are a few recommendations to keep in mind:

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
    not compatible. In other words, a test should be filtered in/out using `if
    runtime.GOOS` rather than a `//go:build` constraint. Here is an
    [example](https://github.com/google/osv-scalibr/commit/7a87679f5c688e7bac4527d29c1823597a52bb40#diff-72efad005e0fbfe34c60e496dfb55ec15fc50f4b12be0934f08a3acaf7733616L79).

## Custom logging

You can make the OSV-SCALIBR library log using your own custom logger by passing
an implementation of the [`log.Logger`](/log/log.go#L22) interface to
`log.SetLogger()`:

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

Read how to [contribute to OSV-SCALIBR](CONTRIBUTING.md).

Look for any [open issues](https://github.com/google/osv-scalibr/issues?q=is%3Aissue%20state%3Aopen%20-label%3APRP)
or [unowned Patch Reward work](https://github.com/google/osv-scalibr/issues?q=is%3Aissue%20state%3Aopen%20label%3APRP%3AInactive)
you'd like to contribute to.

To build and test your local changes, run `make` and `make test`. A local
`scalibr` binary will be generated in the repo base.

Some of your code contributions might require regenerating protos. This can
happen when, say, you want to contribute a new inventory type. For such cases,
you'll need to install a few dependencies:

*   `protoc`: Install the appropriate
    [precompiled protoc binary](https://grpc.io/docs/protoc-installation/#install-pre-compiled-binaries-any-os).
    *   For Mac, you can also
        [install via HomeBrew](https://grpc.io/docs/protoc-installation/#install-using-a-package-manager).
*   `protoc-gen-go`: Run `go install
    google.golang.org/protobuf/cmd/protoc-gen-go`

and then run `make protos` or `./build_protos.sh`.

## Disclaimers

OSV-SCALIBR is not an official Google product.
