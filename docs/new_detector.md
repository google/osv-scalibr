# Adding a new SCALIBR Detector

Detectors are plugins that SCALIBR uses to detect security findings such as
vulnerabilities on the scanned artifact. They all implement the `Detector`
interface and have read access to all files on the filesystem through it.

<!--  See detector/detector.go symbol \bDetector\b -->

<!--  See plugin/plugin.go symbol \bPlugin\b -->

## Steps for writing a new detector

See the [/etc/shadow weak credentials detector](/detector/weakcredentials/etcshadow/etcshadow.go)
as an example.

1.  Set up your detector package in an [appropriate location](#code-location).
1.  Add a `New()` function that returns your detector struct from the specified
    plugin config.
1.  If you'd like to add new plugin-specific config settings for your Detector,
    1. Add them as a new message to [config.proto](third_party/scalibr/binary/proto/config.proto).
    1. Re-generate the go_proto:

        ```
        $ `make protos`
        ```
1.  Implement the [`Detector`](/detector/detector.go)
    interface with your struct:
    *  Implement `Name()` to return a unique name, e.g. `cve/nginxldapauth`.
    *  Implement `Version()` to return 0. Increase it in the future whenever
       larger changes are made to the detector.
    *  Implement `DetectedFinding()` to return [generic info](#output-format)
       about what is detected.
    *  Implement `Scan()` (see [param list](#scan-parameters)) to run your
       detection logic and [return](#output-format) the security findings.
1.  Write tests.
1.  Register your detector in
    [list.go](/detector/list/list.go)
    so you can use it in the CLI.
1.  Update `docs/supported_inventory_types.md` to include your new detector.
1.  If you added new dependencies, regenerate the go.mod file by running

    ```sh
    $ `go mod tidy`
    ```

1.  Test your new detector on a local machine, using the plugin `Name()` to
    enable it, e.g.

    ```
    scalibr --detectors=cve/nginxldapauth ...
    ```

    See the
    [README](/README.md#as-a-standalone-binary)
    for more details on how to run SCALIBR locally.

1.  Submit your code for review.

Once your code is merged, you can add your detector to the list of available
detectors in
[detector/list/list.go](/detector/list/list.go).
Please submit this code separately from the main detector logic.

## Code location

All new detectors should be in a sub-folder of
[detector/](/detector/).
If there's already a directory that fits the detector's category (e.g. cis)
place it in there. Otherwise, feel free to create a new directory. Feel free
to ask SCALIBR devs for location suggestions during code review.

## Scan parameters

Detectors can access the filesystem and the results of the package extraction
step through the parameters of their `Scan()` function.

### Filesystem access

Detectors receive a [`fs.FS`](https://pkg.go.dev/io/fs#FS) implementation which
allows them to read the contents and permissions of any file on the scanned
filesystem. Note that the access is read-only: Detectors are not able to make
changes to the target machine.

### Package index

Detectors also receive a
[`PackageIndex`](/packageindex/package_index.go)
param that can be used to query the software package that the extraction step
found on the filesystem. This can be used to run the detection logic on each relevant
software found, or exit early if none are installed. For an example use case see the
[govulncheck Detector](/detector/govulncheck/binary/binary.go).

## Output format

Detectors return their vulnerability findings in the
[`Finding`](/inventory/finding.go)
struct. Package related vulnerabilities use the `PackageVuln` struct while more
generic findings use `GenericFinding`. Feel free to add a new struct if you're
planning to introduce a new category of vulnerabilities to scan for.
See the comments in the `Finding` struct and
[existing Detector implementations](/detector/govulncheck/binary/binary.go)
for guidance on how to fill these structs out.

One thing to keep in mind: `GenericFindings` are uniquely identified by the
`GenericFindingAdvisory` field, including the `AdvisoryID`. A detector should
always return the same `GenericFindingAdvisory` with its own unique
`AdvisoryID`. If you want to set target-specific information
(e.g. which users had weak passwords), you can add it
to `GenericFindingTargetDetails`.

`PackageVulns` are uniquely identified by the contents of their `Vulnerability`
field. A detector should thus always return the same `Vulnerability`, with the
exception of the `DatabaseSpecific` field. If you want to set target-specific
information (e.g. the exact version of the vulnerable package found), you can
add it to the `DatabaseSpecific` field of `Vulnerability`.

Since `DetectedFinding()` returns generic info about the vulnerability, you'll
generally want to return a `GenericFinding` struct with only the
`GenericFindingAdvisory` or a `PackageVuln` struct with only the `Vulnerability`
(and no `DatabaseSpecific`) field set.

Make sure you appropriately fill the "Description" and "Recommendation" fields
of these structs.

In case you have any questions or feedback, feel free to open an issue.
