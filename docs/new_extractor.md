# Add a new Extractor

Extractors are plugins that extract a inventory information, represented by the
Inventory struct. They are called on every file of system (filesystem
extractor).

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

## What you need to implement

They have to implement the
[Extractor](https://github.com/google/osv-scalibr/blob/28397d99/extractor/filesystem/extractor.go#L45)
interface.

<!--  See extractor/filesystem/filesystem.go symbol \bExtractor\b -->

<!--  See plugin/plugin.go symbol Plugin -->

Here is a simplified version of how SCALIBR will call the filesystem extractor
like this
([actual code](https://github.com/google/osv-scalibr/blob/28397d99/extractor/filesystem/extractor.go#L99)):

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

`FileRequired` should pre filter the files by their filename and fileMode.

`Extract` will be called on each file `FileRequired` returned true for. You
don't have to care about opening files, permissions or closing the file. SCALIBR
will take care of this.

## Input

SCALIBR will call `Extract` with
[ScanInput](https://github.com/google/osv-scalibr/blob/28397d99/extractor/filesystem/extractor.go#L55),
which contains the path, `fs.FileInfo` and `io.Reader` for the file.

<!--  See extractor/filesystem/filesystem.go symbol ScanInput -->

## Output

The `Extract` method should return an [Inventory](https://github.com/google/osv-scalibr/tree/main/inventory/inventory.go) struct.

<!--  See inventory/inventory.go symbol \bInventory\b -->

The Inventory struct should have its appropriate fields set (e.g. `Packages`
for software packages):

<!--  See extractor/extractor.go symbol \bPackage\b -->

You can return an empty Inventory struct in case you don't find software
packages or other inventory in the file. You can also add multiple Package
entries in case there are multiple in one file.

## Code location

Extractors should be in a sub folder of
[/extractor/](/extractor/)

Use this decision tree to identify where to add the extractor.

-   Is the extractor for a specific language? (Java, Go, Python, etc)
    -   **Yes**: Add the extractor under
        [extractor/language/](/extractor/filesystem/language/)
        using the format: `language/[LANGUAGE]/[EXTRACTION_TARGET]`. For
        example, the location for a JavaScript
        [`package.json`](https://docs.npmjs.com/cli/v9/configuring-npm/package-json)
        extractor would be
        [`language/javascript/packagejson/`](/extractor/filesystem/language/javascript/packagejson/).
-   Is the extractor for an OS or OS package manager? (Debian, Linux, etc)
    -   **Yes**: Add the extractor under
        [extractor/os](/extractor/filesystem/os)
        using the format: `os/[PACKAGE_MANAGER]`. For example, the location for
        a Debian based [dpkg](https://man7.org/linux/man-pages/man1/dpkg.1.html)
        extractor would be `os/dpkg`.
-   Is the extractor for an SBOM format? (SPDX, etc)
    -   **Yes**: Add the extractor under
        [extractor/sbom/](/extractor/filesystem/sbom/)
        using the format: `sbom/[FORMAT]/`. For example, the location for an
        [SPDX](https://spdx.dev/) file extractor would be `sbom/spdx`.
-   Is the extractor for something else?
    -   **Yes**: Reach out to the SCALIBR devs,
        e.g. by opening an issue.

## Step by step

You can take the [package.json](/extractor/filesystem/language/javascript/packagejson/packagejson.go)
extractor as an example.

1.  Implement `Name()` to return a unique name. Best practice is to use the path
    such as `python/requirements`, `javascript/packagejson`, `debian/dpkg`,
    `sbom/spdx`.
1.  Implement `Version()` to return 0 and increase it when you do substantial
    changes to the code. Version is used to track when bugs are introduced and
    fixed for a given extractor.
1.  Implement `FileRequired` to return true in case filename and fileMode
    matches a file you need to parse. For example, the JavaScript `package.json`
    extractor returns true for any file named `package.json`.
1.  Implement `Extract` to extract inventory inside the file.
1.  If you introduced any new metadata type, be sure to add them to the scan_results.proto
    as well and re-generate the go_proto:

    ```
    $ `make protos`
    ```

1.  If you added new dependencies, regenerate the go.mod file by running

    ```sh
    $ `go mod tidy`
    ```

1.  Implement `ToPURL` to generate PURLs from the Inventory
    extracted. If your extractor doesn't support CPEs feel free to return an empty
    list.
1.  Write tests (you can separate tests for FileRequired and Extract, to avoid
    having to give test data specific file names).
1.  Register your extractor in
    [list.go](/extractor/filesystem/list/list.go)
1.  Optional: test locally, use the name of the extractor given by `Name()` to
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
