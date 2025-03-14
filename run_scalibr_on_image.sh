#!/bin/bash

# Pulls a container image and runs SCALIBR's extraction plugins on it,
# producing a scalibr-result.textproto in the current directory.
# Example usage: ./run_scalibr_on_image.sh alpine:latest

set -ex
# Create a temp directory for SCALIBR.
tmp=$(mktemp -d)
function cleanup {
  rm -rf "$tmp"
}

# Register the cleanup function to be called on the EXIT signal.
trap cleanup EXIT

# Build SCALIBR and copy it into the tmp dir.
touch "$tmp/scalibr-result.textproto"
make scalibr-static
cp -f scalibr "$tmp/scalibr"
chmod -R 777 $tmp

# Mount the dir containing SCALIBR and run it on the container.
docker run --entrypoint "" -v "$tmp:/scalibr_working_dir:rw" "$1" /scalibr_working_dir/scalibr --result=/scalibr_working_dir/scalibr-result.textproto  --root=/  --extractors=all,untested --skip-dirs=/scalibr_working_dir

# Move the results to the CWD.
cp $tmp/scalibr-result.textproto scalibr-result.textproto
