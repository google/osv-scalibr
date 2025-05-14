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

package extractor

import (
	hexpurl "github.com/google/osv-scalibr/extractor/filesystem/language/erlang/mixlock/purl"
	gopurl "github.com/google/osv-scalibr/extractor/filesystem/language/golang/purl"
	mavenpurl "github.com/google/osv-scalibr/extractor/filesystem/language/java/purl"
	npmpurl "github.com/google/osv-scalibr/extractor/filesystem/language/javascript/purl"
	"github.com/google/osv-scalibr/extractor/filesystem/language/python/pypipurl"
	winpurl "github.com/google/osv-scalibr/extractor/standalone/windows/common/purl"
	"github.com/google/osv-scalibr/purl"
)

// ToPURL converts a SCALIBR package structure into a package URL.
func toPURL(p *Package) *purl.PackageURL {
	if p.PURLType == "" {
		return nil
	}
	// See if this needs any special type-specific conversion logic.
	if purl := typeSpecificPURL(p); purl != nil {
		return purl
	}
	// All other cases: Set just the name and version.
	return &purl.PackageURL{
		Type:    p.PURLType,
		Name:    p.Name,
		Version: p.Version,
	}
}

func typeSpecificPURL(p *Package) *purl.PackageURL {
	switch p.PURLType {
	case purl.TypePyPi:
		return pypipurl.MakePackageURL(p.Name, p.Version)
	case purl.TypeMaven:
		return mavenpurl.MakePackageURL(p.Version, p.Metadata)
	case purl.TypeNPM:
		return npmpurl.MakePackageURL(p.Name, p.Version)
	case purl.TypeGolang:
		return gopurl.MakePackageURL(p.Name, p.Version)
	case purl.TypeHex:
		return hexpurl.MakePackageURL(p.Name, p.Version)
	case "windows":
		return winpurl.MakePackageURL(p.Name, p.Version, p.Metadata)
	}
	// TODO(b/400910349): Add remaining type-specific conversion logic.
	return nil
}
