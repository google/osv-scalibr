# Adding a new SCALIBR Enricher

Enrichers are plugins that SCALIBR uses to enrich results from other plugins
(e.g. Extractors, Detectors) with data from external sources (e.g. package
information from deps.dev or vulnerabilities from osv.dev). They all implement
the `Enricher` interface which provides the ability to:

-   Access files on the filesystem being scanned through the
    [enrich parameters](#enrich-parameters) (⚠️ **discouraged: Detectors or
    Annotators should be used if possible**).
-   Mutate results from other plugins.

<!--  See enricher/enricher.go symbol \bEnricher\b -->

<!--  See plugin/plugin.go symbol Plugin -->

## Implementation Steps

See the
[Base Image Enricher](/enricher/baseimage/baseimage.go)
as an example.

1.  Set up your enricher package in an [appropriate location](#code-location).
1.  Create a struct that implements
    [`Enricher`](/enricher/enricher.go):
    *   Implement `Name()` to return a unique name, e.g. `baseimage`.
    *   Implement `Version()` to return 0. Increase it in the future whenever
        larger changes are made to the enricher.
    *   Implement `Enrich()` (see [param list](#enrich-parameters)) to run your
        enricher logic and augment [update inventory](#update-inventory) with
        new data.
1.  Write tests.
1.  Register your enricher in
    [list.go](/enricher/enricherlist/list.go)
    so you can use it in the CLI.
1.  Update `docs/supported_inventory_types.md` to include your new enricher.
1.  If you added new dependencies, regenerate the go.mod file by running

    ```sh
    $ `go mod tidy`
    ```

1.  Test your new enricher on a local machine, using the plugin `Name()` to
    enable it, e.g.

    ```
    scalibr --plugins=baseimage ...
    ```

    See the
    [README](/README.md#as-a-standalone-binary)
    for more details on how to run SCALIBR locally.

1.  Send the code out for review.

## Code location

All new enrichers should be in a sub-folder of
[enricher/](/enricher/). If there's already a
directory that fits the enricher's category (e.g. `enricher/java` for enrichers
that add data to Java packages) place it in there. Otherwise, feel free to
create a new directory.

## Enrich parameters

Enrichers accept two parameters:

-   `ScanInput`: access to the filesystem or on-host information.
-   `Inventory`: the output of other plugins.

Although Enrichers can optionally access the filesystem, this is discouraged in
most cases, and `ScanInput` should be `nil`.

## Network access

Enrichers are primarily used to access APIs and update scan results. Because of
this, Enrichers must explicitly convey this in their `Requirements`:

```
// Requirements of the my enricher.
func (*Enricher) Requirements() *plugin.Capabilities {
    return &plugin.Capabilities{Network: plugin.NetworkOnline}
}
```

## Update inventory

Enrichers mutate inventory returned by other plugins. They can:

-   Add new objects or fields.
-   Update existing objects or fields.
-   Delete objects or fields.

Below is an illustrative example. In the example the:

1.  Java Reachability Enricher adds whether certain packages are reachable (can
    be run).
1.  OSV Enricher adds new vulnerability findings from osv.dev.
1.  VEX Enricher filters out vulnerabilities that are unreachable (cannot be
    exploited).

🟢 denotes objects or fields mutated (add, update, delete) by the previous
enricher.

```sequence-diagram
Title: Flow of inventory\nthrough plugins

Java Extractor->>Java Reachability Enricher: {{package: "foo", version: "1.2"},\n{package: "bar", version: "2.3"}}
Java Reachability Enricher->>OSV Enricher: {{package: "foo", version: "1.2" 🟢 reachable: "true"},\n{package: "bar", version: "2.3", 🟢 reachable: "false"}}
OSV Enricher->>VEX Enricher: {{package: "foo", version: "1.2" reachable: "true"},\n{package: "bar", version: "2.3", reachable: "false"},\n🟢 finding: {id: "CVE-123", package: "foo"},\n🟢 finding: {id: "CVE-456", package: "bar"}}
VEX Enricher->>Output: {{package: "foo", version: "1.2" reachable: "true"},\n{package: "bar", version: "2.3", reachable: "false"},\nfinding: {id: "CVE-123", package: "foo"},\n🟢 \[REMOVED CVE-456\]}
```

## Questions

In case you have any questions or feedback, feel free to open an issue.
