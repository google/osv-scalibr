// Copyright 2026 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package proto

import (
	spb "github.com/google/osv-scalibr/binary/proto/scan_result_go_proto"
	"github.com/google/osv-scalibr/inventory/location"
)

func LocationToStruct(l *spb.Location) *location.Location {
	if l == nil {
		return nil
	}
	res := &location.Location{}

	if l.File != nil {
		res.File = fileToStruct(l.File)
	}

	return res
}

func LocationToProto(l *location.Location) *spb.Location {
	if l == nil {
		return nil
	}
	res := &spb.Location{}

	if l.File != nil {
		res.File = fileToProto(l.File)
	}

	return res
}

func fileToStruct(file *spb.File) *location.File {
	return &location.File{Path: file.Path, LineNumber: int(file.LineNumber)}
}

func fileToProto(file *location.File) *spb.File {
	return &spb.File{Path: file.Path, LineNumber: int32(file.LineNumber)}
}
