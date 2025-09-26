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

	spb "github.com/google/osv-scalibr/binary/proto/scan_result_go_proto"
	"github.com/google/osv-scalibr/extractor/filesystem/language/dotnet/depsjson"
	javascriptmeta "github.com/google/osv-scalibr/extractor/filesystem/language/javascript/packagejson/metadata"
	"github.com/google/osv-scalibr/extractor/filesystem/language/python/wheelegg"
	apkmeta "github.com/google/osv-scalibr/extractor/filesystem/os/apk/metadata"
	cosmeta "github.com/google/osv-scalibr/extractor/filesystem/os/cos/metadata"
	dpkgmeta "github.com/google/osv-scalibr/extractor/filesystem/os/dpkg/metadata"
	flatpakmeta "github.com/google/osv-scalibr/extractor/filesystem/os/flatpak/metadata"
	"github.com/google/osv-scalibr/extractor/filesystem/os/macapps"
	macportsmeta "github.com/google/osv-scalibr/extractor/filesystem/os/macports/metadata"
	nixmeta "github.com/google/osv-scalibr/extractor/filesystem/os/nix/metadata"
	pacmanmeta "github.com/google/osv-scalibr/extractor/filesystem/os/pacman/metadata"
	portagemeta "github.com/google/osv-scalibr/extractor/filesystem/os/portage/metadata"
	rpmmeta "github.com/google/osv-scalibr/extractor/filesystem/os/rpm/metadata"
	snapmeta "github.com/google/osv-scalibr/extractor/filesystem/os/snap/metadata"
	wingetmeta "github.com/google/osv-scalibr/extractor/filesystem/os/winget/metadata"
	asdfmeta "github.com/google/osv-scalibr/extractor/filesystem/runtime/asdf/metadata"
	nodeversionmeta "github.com/google/osv-scalibr/extractor/filesystem/runtime/nodejs/nodeversion/metadata"
	nvmmeta "github.com/google/osv-scalibr/extractor/filesystem/runtime/nodejs/nvm/metadata"
	"github.com/google/osv-scalibr/extractor/standalone/os/netports"
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
		reflect.TypeOf(&spb.Package_NetportsMetadata{}): func(p *spb.Package) any {
			return netports.ToStruct(p.GetNetportsMetadata())
		},
		reflect.TypeOf(&spb.Package_ApkMetadata{}): func(p *spb.Package) any {
			return apkmeta.ToStruct(p.GetApkMetadata())
		},
		reflect.TypeOf(&spb.Package_DpkgMetadata{}): func(p *spb.Package) any {
			return dpkgmeta.ToStruct(p.GetDpkgMetadata())
		},
		reflect.TypeOf(&spb.Package_SnapMetadata{}): func(p *spb.Package) any {
			return snapmeta.ToStruct(p.GetSnapMetadata())
		},
		reflect.TypeOf(&spb.Package_RpmMetadata{}): func(p *spb.Package) any {
			return rpmmeta.ToStruct(p.GetRpmMetadata())
		},
		reflect.TypeOf(&spb.Package_CosMetadata{}): func(p *spb.Package) any {
			return cosmeta.ToStruct(p.GetCosMetadata())
		},
		reflect.TypeOf(&spb.Package_PacmanMetadata{}): func(p *spb.Package) any {
			return pacmanmeta.ToStruct(p.GetPacmanMetadata())
		},
		reflect.TypeOf(&spb.Package_PortageMetadata{}): func(p *spb.Package) any {
			return portagemeta.ToStruct(p.GetPortageMetadata())
		},
		reflect.TypeOf(&spb.Package_FlatpakMetadata{}): func(p *spb.Package) any {
			return flatpakmeta.ToStruct(p.GetFlatpakMetadata())
		},
		reflect.TypeOf(&spb.Package_NixMetadata{}): func(p *spb.Package) any {
			return nixmeta.ToStruct(p.GetNixMetadata())
		},
		reflect.TypeOf(&spb.Package_MacAppsMetadata{}): func(p *spb.Package) any {
			return macapps.ToStruct(p.GetMacAppsMetadata())
		},
		reflect.TypeOf(&spb.Package_AsdfMetadata{}): func(p *spb.Package) any {
			return asdfmeta.ToStruct(p.GetAsdfMetadata())
		},
		reflect.TypeOf(&spb.Package_NvmMetadata{}): func(p *spb.Package) any {
			return nvmmeta.ToStruct(p.GetNvmMetadata())
		},
		reflect.TypeOf(&spb.NodeVersionMetadata{}): func(p *spb.Package) any {
			return nodeversionmeta.ToStruct(p.GetNodeversionMetadata())
		},
		reflect.TypeOf(&spb.Package_MacportsMetadata{}): func(p *spb.Package) any {
			return macportsmeta.ToStruct(p.GetMacportsMetadata())
		},
		reflect.TypeOf(&spb.Package_WingetMetadata{}): func(p *spb.Package) any {
			return wingetmeta.ToStruct(p.GetWingetMetadata())
		},
	}

	_ = []MetadataProtoSetter{
		(*wheelegg.PythonPackageMetadata)(nil),
		(*javascriptmeta.JavascriptPackageJSONMetadata)(nil),
		(*depsjson.Metadata)(nil),
		(*netports.Metadata)(nil),
		(*apkmeta.Metadata)(nil),
		(*dpkgmeta.Metadata)(nil),
		(*snapmeta.Metadata)(nil),
		(*rpmmeta.Metadata)(nil),
		(*cosmeta.Metadata)(nil),
		(*pacmanmeta.Metadata)(nil),
		(*portagemeta.Metadata)(nil),
		(*flatpakmeta.Metadata)(nil),
		(*nixmeta.Metadata)(nil),
		(*macapps.Metadata)(nil),
		(*asdfmeta.Metadata)(nil),
		(*nvmmeta.Metadata)(nil),
		(*nodeversionmeta.Metadata)(nil),
		(*macportsmeta.Metadata)(nil),
		(*wingetmeta.Metadata)(nil),
	}
)
