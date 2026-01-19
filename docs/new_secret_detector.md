# Add a new Veles secret detector and validator

Veles secret detectors and validator are plugins for the
[Veles](/veles) library to find leaked or
overshared credentials.

[Detectors](/veles/detect.go) look for secret
candidates on the artifact's filesystem and return them in a sub-type of the
[Secret](/veles/secret.go) struct.
[Validators](/veles/validate.go#L41) perform
API queries to check if the secret is still in use, and return a corresponding
[ValidationStatus](/veles/validate.go). When
adding support for detecting a new secret type, prefer to add both a Detector
and a Validator to minimize the occurrence of false positives.

## Steps for writing new secret detectors and validators

Some examples:
[DigitalOcean API key](/veles/secrets/digitaloceanapikey)
for a simple scanner and
[GCP SAK](/veles/secrets/gcpsak) for a more
complicated scanner.

1.  Set up your secret package under
    [veles/secrets/](/veles/secrets/).
1.  Create a
    [secret type](/veles/secrets/digitaloceanapikey/digitaloceanapikey.go)
    containing all important fields we should store for the secret. And add
    [proto conversion](#proto-conversion) for it.
1.  Implement the [detection plugin](#detector-plugin) for the secret.
1.  Implement the [validation plugin](#validator-plugin) for the secret.
1.  Register the plugins in the `list.go` files for
    [extractors](/extractor/filesystem/list/list.go)
    and
    [validators](/enricher/enricherlist/list.go).
1.  [Test](#e2e-testing) your secret scanner end-to-end.

## Proto conversion

To surface detected secrets in the SCALIBR output proto, a proto equivalent of
the secret type should be added to
[scan_result.proto](/binary/proto/scan_result.proto),
and the conversion code between the Go struct and the proto to
[proto/secret.go](/binary/proto/secret.go).

Make sure to re-generate the go_proto files once you edit scan_result.proto:
```
$ `make protos`
```

## Detector plugin

Secret detectors implement the
[veles.Detector](/veles/detect.go) interface,
which provides a method to return secrets and their positions found in a byte
array.

<!--  See veles/detect.go symbol \bDetector\b -->

This interface
[gets converted](/extractor/filesystem/list/list.go#L300)
into a classic SCALIBR filesystem extractor plugin further in the pipeline.

If the secret can only be detected with additional filesystem-level context such
as the name of the file (e.g. Postgres pgpass secrets are always inside .pgpass
files) you can implement your detector
[as a filesystem.Extractor directly](new_extractor.md) or use
[convert.FromVelesDetectorWithRequire](/extractor/filesystem/secrets/awsaccesskey/awsaccesskey.go)
to add file name requirements.

In most cases the detection logic is simply looking for regexps in the byte
array. If this is the case with your secret type you can use the
[simpletoken](/veles/secrets/common/simpletoken/simpletoken.go)
library to make your plugin simpler.

When writing unit tests, make sure to register an [acceptance test](/veles/secrets/github/pat_classic_detector_test.go#L21)
for each new secret type for better coverage of the detection code.

## Validator plugin

Secret validators implement the
[veles.Validator](/veles/validate.go)
interface for the given secret type. The validation method normally performs API
calls with the given secret and returns whether the secret was found valid.

<!--  See veles/validate.go symbol \bValidator\b -->

Oftentimes the validation logic simply calls an HTTP endpoint with the given
secret included in the headers and decides on the validation logic based on the
contents of the response body or status code. If this is the case with your
validator you can use the
[simplevalidate](/veles/secrets/common/simplevalidate/simplevalidate.go)
library which takes care of most of the boilerplate for you.

Validators are for validation steps that requires networking. Other types of
validation logic (e.g. cryptographically validating the a GCP key candidate) can
be performed inside the Detector implementation.

## e2e Testing

Once the detection and validation logic is wired up, you can verify your plugins
through the SCALIBR CLI end-to-end. To do so,

1.  Generate a valid secret you'd like to test and add it to a file on your
    filesystem, e.g. /path/to/secret.txt
1.  Run SCALIBR, enabling secret scanning and pointing it to the file you
    created:

    ```
    ./scalibr --plugins=secrets,secretsvalidate --result=scan-result.textproto /path/to/secret.txt
    ```

1.  Verify that the secret has been found and was considered valid.

In case you have any questions or feedback, feel free to open an issue.
