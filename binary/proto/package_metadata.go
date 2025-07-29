// Copyright 2025 Google LLC
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
	"reflect"

	"github.com/google/osv-scalibr/extractor/filesystem/language/dotnet/depsjson"
	javascriptmeta "github.com/google/osv-scalibr/extractor/filesystem/language/javascript/packagejson/metadata"
	"github.com/google/osv-scalibr/extractor/filesystem/language/python/wheelegg"

	spb "github.com/google/osv-scalibr/binary/proto/scan_result_go_proto"
)

var (
	metadataTypeToStructConverter = map[reflect.Type]func(*spb.Package) any{
		reflect.TypeOf(&spb.Package_PythonMetadata{}): func(p *spb.Package) any {
			return wheelegg.ToStruct(p.GetPythonMetadata())
		},
		reflect.TypeOf(&spb.Package_JavascriptMetadata{}): func(p *spb.Package) any {
			return javascriptmeta.ToStruct(p.GetJavascriptMetadata())
		},
		reflect.TypeOf(&spb.Package_DepsjsonMetadata{}): func(p *spb.Package) any {
			return depsjson.ToStruct(p.GetDepsjsonMetadata())
		},
	}
)
