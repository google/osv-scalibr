#!/bin/sh
# Copyright 2025 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http:#www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.



[ binary/proto/scan_result_go_proto/scan_result.pb.go -ot binary/proto/scan_result.proto ]
REGEN_RESULT=$?
[ binary/proto/config_go_proto/config.pb.go -ot binary/proto/config.proto ]
REGEN_CONFIG=$?

# Install and prepare osv-schema protos.
if [ "$REGEN_RESULT" -eq 0 ] || [ "$REGEN_CONFIG" -eq 0 ]; then
  OSV_SCHEMA_VERSION="1.7.4"
  wget --no-verbose https://github.com/ossf/osv-schema/archive/refs/tags/v$OSV_SCHEMA_VERSION.tar.gz
  tar -xf v$OSV_SCHEMA_VERSION.tar.gz
  mv osv-schema-$OSV_SCHEMA_VERSION/proto/vulnerability.proto binary/proto/vulnerability.proto
  rm -r v$OSV_SCHEMA_VERSION.tar.gz osv-schema-$OSV_SCHEMA_VERSION
fi

# Compile scan_result.proto if it changed.
if [ "$REGEN_RESULT" -eq 0 ]; then
  rm -rf binary/proto/scan_result_go_proto
  protoc -I=binary --go_out=binary/proto binary/proto/scan_result.proto
  mv binary/proto/github.com/google/osv-scalibr/binary/proto/scan_result_go_proto binary/proto/
fi

# Compile config.proto if it changed.
if [ "$REGEN_CONFIG" -eq 0 ]; then
  rm -rf binary/proto/config_go_proto
  protoc -I=binary --go_out=binary/proto binary/proto/config.proto
  mv binary/proto/github.com/google/osv-scalibr/binary/proto/config_go_proto binary/proto/
fi

# Clean up
rm -rf binary/proto/github.com binary/proto/vulnerability.proto
