# Adding a new SCALIBR Enricher

Enrichers are plugins that SCALIBR uses to enrich results from other plugins
(e.g. Extractors, Detectors) with data from external sources
(e.g. package information from deps.dev or vulnerabilities from osv.dev).
They all implement the `Enricher` interface which provides the ability to:

- Access files on the filesystem being scanned (⚠️ **discouraged: Detectors should be used if possible**).
- Mutate results from other plugins.

<!--  See enricher/enricher.go symbol \bEnricher\b -->

<!--  See plugin/plugin.go symbol Plugin -->

## Implementation Steps

See the [Base Image Enricher](/enricher/baseimage/baseimage.go)
as an example.

1. Set up your enricher package in an [appropriate location](#code-location).
1.  Create a struct that implements
    [`Enricher`](/enricher/enricher.go):
    *  Implement `Name()` to return a unique name, e.g. `baseimage`.
    *   Implement `Version()` to return 0. Increase it in the future whenever
        larger changes are made to the enricher.
    *   Implement `Enrich()` (see [param list](#enrich-parameters)) to run your
        enricher logic and augment [update inventory](#update-inventory) with new data.
1.  Write tests.
1.  Send the enricher code out for review.
1.  Register your enricher in
    [list.go](/enricher/enricherlist/list.go)
    so you can use it in the CLI.
1.  If you added new dependencies, regenerate the go.mod file by running

    ```sh
    $ `go mod tidy`
    ```

1.  Test your new enricher on a local machine, using the plugin `Name()` to
    enable it, e.g.

    ```
    scalibr --plugins=enricher/baseimage ...
    ```

    See the
    [README](/README.md#as-a-standalone-binary)
    for more details on how to run SCALIBR locally.

1.  Send your the list and CLI code out for review.

## Code location

All new enrichers should be in a sub-folder of
[enricher/](/enricher/).
If there's already a directory that fits the enricher's category
(e.g. `enricher/java` for enrichers that add data to Java packages)
place it in there. Otherwise, feel free to create a new directory.

## Enrich parameters

Enrichers are primarily used to access APIs and update scan results.
Although Enrichers can optionally access the filesystem,
this is discouraged in most cases.

## Update inventory

Enrichers mutate inventory returned by other plugins. They can:

- Update existing fields.
- Add new fields.
- Add new objects.

They can delete fields and objects, but this is discouraged.

Below is an illustrative example:

```sequence-diagram
Title: Flow of inventory through plugins

Java Extractor->>Java Reachability Enricher: {{package: "foo",\nversion: "1.2"}}
Java Reachability Enricher->>OSV Enricher: {{package: "foo",\nversion: "1.2",\n🟢 reachable: "true"}}
OSV Enricher->>Output: {{package: "foo",\nversion: "1.2",\nreachable: "true"},\n🟢 finding: {id: "CVE-123"}}
```

## Questions

In case you have any questions or feedback, feel free to open an issue.
