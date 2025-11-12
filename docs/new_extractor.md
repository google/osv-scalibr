# Add a new Extractor

Extractors are plugins that extract inventory information, represented by the
Inventory struct. They are either called on every file on the host (filesystem
extractor) or query files on their own (standalone extractor).

There should be one Extractor per parsing logic. In python for example there are
multiple files to represent installed packages. `PKG-INFO`, `egg-info` and
`METADATA` have the same format (MIME type) and therefore same parsing logic.
Therefore there is one extractor
([wheelegg](/extractor/filesystem/language/python/wheelegg/wheelegg.go))
for all of them. `.egg` files are zip files which contain one of the previously
mentioned files, thus `.egg` is also handled by this extractor. On the other
side, there are files which have a different format, e.g. `requirements.txt`,
which is just a list of packages. Thus `requirements.txt` gets a separate
extractor.

```
wheel_egg/ <- extractor
  **/*egg-info/PKG-INFO
  */.egg-info
  **/*dist-info/METADATA
  **/EGG-INFO/PKG-INFO
  .egg
requirements/ <- extractor
  requirements.txt
...
```

## Extractor interfaces

Extractors use the [filesystem.Extractor](https://github.com/google/osv-scalibr/blob/f37275e81582aee9/extractor/standalone/standalone.go#L30)
or [standalone.Extractor](https://github.com/google/osv-scalibr/blob/f37275e81582aee9/extractor/standalone/standalone.go#L30) interface.

### Filesystem Extractors

<!--  See extractor/filesystem/filesystem.go symbol \bExtractor\b -->

<!--  See plugin/plugin.go symbol \bPlugin\b -->

`FileRequired` should pre filter the files by their filename and fileMode.

`Extract` will be called on each file `FileRequired` returned true for. You
don't have to care about opening files, permissions or closing the file. SCALIBR
will take care of this.

Here is a simplified version of how SCALIBR will call the filesystem extractor
like this
([actual code](https://github.com/google/osv-scalibr/blob/f37275e81582aee9/extractor/standalone/standalone.go#L49)):

```py
for f in walk.files:
  for e in filesystemExtractors:
    if e.FileRequired(f):
      fh = open(f)
      inventory.add(e.Extract(fh))
      fh.close()
for e in standaloneExtractors:
  inventory.add(e.Extract(fs))
```

SCALIBR will call `Extract` with
[ScanInput](https://github.com/google/osv-scalibr/blob/f37275e81582aee9/extractor/standalone/standalone.go#L43),
which contains the path, `fs.FileInfo` and `io.Reader` for the file. It also
contains a FS interface and the scan root in case the extractor needs to access
other files on the host.

<!--  See extractor/filesystem/filesystem.go symbol \bScanInput\b -->

### Standalone Extractors

<!--  See extractor/standalone/standalone.go symbol \bExtractor\b -->

`Extract` receives a [ScanInput](https://github.com/google/osv-scalibr/blob/f37275e81582aee9/extractor/standalone/standalone.go#L43)
that gives it access to the root of the scanned host. Use this to read the files
you're interested in.

### Output

For both extractors, the `Extract` method should return an [Inventory](https://github.com/google/osv-scalibr/tree/main/inventory/inventory.go) struct.

<!--  See inventory/inventory.go symbol \bInventory\b -->

The Inventory struct should have its appropriate fields set (e.g. `Packages`
for software packages, `Secrets` for leaked credentials):

<!--  See extractor/extractor.go symbol \bPackage\b -->

You can return an empty Inventory struct in case you don't find software
packages or other inventory in the file. You can also add multiple Package/etc.
entries in case there are multiple in one file.

## Code location

Extractors should be in a sub-folder of
[/extractor/filesystem](/extractor/) or
[/extractor/standalone](/standalone/)
depending on the Extractor type. Take a look at existing folders and pick
whichever is the most appropriate location for your Extractor, or create a new
folder if none of the existing ones apply. Feel free to ask SCALIBR devs for
location suggestions during code review.

## Step by step

You can take the [package.json](/extractor/filesystem/language/javascript/packagejson/packagejson.go)
extractor as an example for Filesystem Extractors.

1.  Add a `New()` function that returns an Extractor from the specified plugin config.
  1.  If you'd like to add new plugin-specific config settings for your Extractor,
    1. Add them as a new message to [config.proto](third_party/scalibr/binary/proto/config.proto).
    1. Re-generate the go_proto:

        ```
        $ `make protos`
        ```

    1. You'll be able to specify these config settings from the CLI with the
       --plugin-config flag.
1.  Implement `Name()` to return a unique name. Best practice is to use the path
    such as `python/requirements`, `javascript/packagejson`, `debian/dpkg`,
    `sbom/spdx`.
1.  Implement `Version()` to return 0. This should be increased later on
    whenever substantial changes are added the code. Version is used to track
    when bugs are introduced and fixed for a given Extractor.
1.  Implement `Requirements()` to return any required [Capabilities](https://github.com/google/osv-scalibr/blob/f37275e81582aee9/plugin/plugin.go#L63)
    for the system that runs the scanner. For example, if your code needs
    network access, return `&plugin.Capabilities{Online: true}`.
    Ideally your Extractor is able to run in any scanning environment
    and will return an empty struct.
1.  (For Filesystem Extractors) Implement `FileRequired` to return true in case
    the filename and fileMode matches a file you need to parse. For example,
    the JavaScript `package.json` extractor returns true for any file
    named `package.json`.
1.  Implement `Extract` to extract inventory inside the current file
    (or from elsewhere on the filesystem).
1.  If you introduced any new metadata type, be sure to:
    1. Add them to the [scan_result.proto](third_party/scalibr/binary/proto/scan_result.proto).
    1. Re-generate the go_proto:

        ```
        $ `make protos`
        ```

    1. Implement `func (m *Metadata) SetProto(p *pb.Package)` and `ToStruct(m *pb.MyMetadata) *Metadata`.
    1. Add the `ToStruct` function to the metadata map in `binary/proto/package_metadata.go`.

1.  If you added new dependencies, regenerate the go.mod file by running:

    ```sh
    $ `go mod tidy`
    ```

1.  If your Inventory is Package which can have a corresponding Package URL,
    check that [extractor.ToPURL](/extractor/convert.go)
    generates a valid PURL for your package's PURL type. Implement your custom
    PURL generation logic here if necessary.
1.  Write tests (you can separate tests for FileRequired and Extract, to avoid
    having to give test data specific file names).
1.  Register your extractor in
    [list.go](/extractor/filesystem/list/list.go)
1.  Update `docs/supported_inventory_types.md` to include your new extractor.
1.  Optional: Test locally: Use the name of the extractor given by `Name()` to
    select your extractor. For the `packagejson` extractor it would look like
    this:

    ```sh
    $ scalibr --extractors=javascript/packagejson ...
    ```

    You can find more details on how to run scalibr in
    [README.md](/README.md#as-a-standalone-binary)

1.  Submit your code for review. Once merged, the extractor is ready to use, but
    not activated in any defaults yet.

To add your extractor to the list of default extractors, add it in
[extractor/list/list.go](/extractor/filesystem/list/list.go).
Please submit this code separately from the main extractor logic.

In case you have any questions or feedback, feel free to open an issue.
