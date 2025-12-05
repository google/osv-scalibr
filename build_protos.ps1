Remove-Item -Recurse -Force binary/proto/*_go_proto

# Install and prepare osv-schema protos.
if (-not (Test-Path binary/proto/vulnerability.proto)) {
  $OSV_SCHEMA_VERSION='1.7.4'
  Invoke-WebRequest -Uri "https://github.com/ossf/osv-schema/archive/refs/tags/v$OSV_SCHEMA_VERSION.tar.gz" -OutFile "v$OSV_SCHEMA_VERSION.tar.gz"
  tar -xf v$OSV_SCHEMA_VERSION.tar.gz
  Move-Item -Path "osv-schema-$OSV_SCHEMA_VERSION/proto/vulnerability.proto" -Destination 'binary/proto/vulnerability.proto'
  Remove-Item -Recurse -Force "v$OSV_SCHEMA_VERSION.tar.gz", "osv-schema-$OSV_SCHEMA_VERSION"
}

# Make sure scan_result.proto is referenceing the vulnerability.proto file on the right path.
# This is only needed to successfully compile the scan_result.proto file.
(Get-Content binary/proto/scan_result.proto) -creplace 'third_party/osvschema/vulnerability.proto', 'proto/vulnerability.proto' | Set-Content binary/proto/scan_result.proto

protoc -I=binary --go_out=binary/proto binary/proto/*.proto
Move-Item binary/proto/github.com/google/osv-scalibr/binary/proto/* binary/proto/
Remove-Item -Recurse -Force binary/proto/github.com, binary/proto/vulnerability.proto
