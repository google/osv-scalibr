// Copyright 2025 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//	http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
package golangpurl

import (
	"strings"

	"github.com/google/osv-scalibr/extractor"
	"github.com/google/osv-scalibr/purl"
)

// MakePackageURL returns a package URL following the purl Golang spec:
// - There is no default package repository: this is implied in the namespace using the go get command conventions.
// - The namespace and name must be lowercased.
//
// See: https://github.com/package-url/purl-spec/blob/master/PURL-TYPES.rst#golang
func MakePackageURL(p *extractor.Package) *purl.PackageURL {
	nameParts := strings.Split(strings.ToLower(p.Name), "/")
	return &purl.PackageURL{
		Type:      purl.TypeGolang,
		Name:      nameParts[len(nameParts)-1],
		Namespace: strings.Join(nameParts[:len(nameParts)-1], "/"),
		Version:   p.Version,
	}
}
