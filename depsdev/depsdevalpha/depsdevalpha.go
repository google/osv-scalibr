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

// Package depsdevalpha contains constants and mappings for the deps.dev v3alpha API.
package depsdevalpha

import (
	pb "deps.dev/api/v3alpha"
	"github.com/google/osv-scalibr/purl"
)

// System maps from purl type to the deps.dev systems.
var System = map[string]pb.System{
	purl.TypeGolang: pb.System_GO,
	purl.TypeGem:    pb.System_RUBYGEMS,
	purl.TypeNPM:    pb.System_NPM,
	purl.TypeCargo:  pb.System_CARGO,
	purl.TypeMaven:  pb.System_MAVEN,
	purl.TypePyPi:   pb.System_PYPI,
	purl.TypeNuget:  pb.System_NUGET,
}
