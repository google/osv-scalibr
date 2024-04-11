# Adding a new SCALIBR Detector

Detectors are plugins that SCALIBR uses to detect security findings such as
vulnerabilities on the scanned artifact. They all implement the `Detector`
interface and have read access to all files on the filesystem through it.

# See detector/detector.go symbol Detector

# See plugin/plugin.go symbol Plugin

## Steps for writing a new detector

See the [CIS benchmark detector](/detector/cis/generic_linux/etcpasswdpermissions/detector.go) as an example.

1.  Set up your detector package in an [appropriate location](#code-location).
1.  Create a struct that implements
    [`Detector`](/detector/detector.go):
    *   Implement `Name()` to return a unique name, e.g. `cve/nginxldapauth`.
    *   Implement `Version()` to return 0. Increase it in the future whenever
        larger changes are made to the detector.
    *   Implement `Scan()` (see [param list](#scan-parameters)) to run your
        detection logic and [return](#output-format) the security findings.
1.  Write tests.
1.  Register your detector in
    [list.go](/detector/list/list.go)
    so you can use it in the CLI.
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
place it in there. Otherwise, feel free to create a new directory.

## Scan parameters

Detectors can access the filesystem and the results of the inventory extraction
step through the parameters of their `Scan()` function.

### Filesystem access

Detectors receive a [`fs.FS`](https://pkg.go.dev/io/fs#FS) implementation which
allows them to read the contents and permissions of any file on the scanned
filesystem. Note that the access is read-only: Detectors are not able to make
changes to the target machine.

### Inventory index

Detectors also receive an
[`InventoryIndex`](/inventoryindex/inventory_index.go)
param that can be used to query the software inventory that the extraction step
found on the filesystem. This can be used to run the detection logic on each relevant
software found, or exit early if none are installed. For an example use case see the
[govulncheck Detector](/detector/govulncheck/binary/detector.go).

## Output format

Detectors return their vulnerability findings in the
[`Finding`](https://github.com/google/osv-scalibr/blob/4d646d6e/detector/detector.go#46)
struct. See the comments in the `Finding` struct and
[existing Detector implementations](/detector/govulncheck/binary/detector.go)
for guidance on how to fill it out. Keep in mind that findings are uniquely
identified by the `AdvisoryID` and each detector should return a unique
`AdvisoryID` for their findings.

In case you have any questions or feedback, feel free to open an issue.
