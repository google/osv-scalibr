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

// Package depsdev contains constants and mappings for the deps.dev API.
package depsdev

import (
	"github.com/google/osv-scalibr/purl"

	depsdevpb "deps.dev/api/v3"
)

// DepsdevAPI is the URL to the deps.dev API. It is documented at
// docs.deps.dev/api.
const DepsdevAPI = "api.deps.dev:443"

// System maps from purl type to the depsdev API system.
var System = map[string]depsdevpb.System{
	purl.TypeNPM:    depsdevpb.System_NPM,
	purl.TypeNuget:  depsdevpb.System_NUGET,
	purl.TypeCargo:  depsdevpb.System_CARGO,
	purl.TypeGolang: depsdevpb.System_GO,
	purl.TypeMaven:  depsdevpb.System_MAVEN,
	purl.TypePyPi:   depsdevpb.System_PYPI,
}
