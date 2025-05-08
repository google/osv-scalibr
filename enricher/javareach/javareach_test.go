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

package javareach_test

import (
	"context"
	"path/filepath"
	"testing"

	"github.com/google/osv-scalibr/enricher"
	"github.com/google/osv-scalibr/enricher/javareach"
	"github.com/google/osv-scalibr/extractor"
	"github.com/google/osv-scalibr/extractor/filesystem/language/java/archive"
	scalibrfs "github.com/google/osv-scalibr/fs"
	"github.com/google/osv-scalibr/inventory"
	"github.com/google/osv-scalibr/purl"
)

const testJar = "hello-tester.jar"
const reachablePkgName = "com.fasterxml.jackson.core:jackson-annotations"
const unreachablePkgName = "org.eclipse.jetty:jetty-continuation"

func TestScan(t *testing.T) {
	enr := javareach.Enricher{}
	px := setupPackageIndex([]string{testJar})
	scalibrfs.RealFSScanRoot(filepath.Join("testdata", testJar))
	input := enricher.ScanInput{
		Root: filepath.Join("testdata", testJar),
	}
	inv := inventory.Inventory{
		Packages: px,
	}
	err := enr.Enrich(context.Background(), &input, &inv)
	if err != nil {
		t.Fatalf("enricher.Enrich(%v): Expected an error, got none", px)
	}

	for _, pkg := range inv.Packages {
		if pkg.Name == reachablePkgName {
			for _, annotation := range pkg.Annotations {
				if annotation == extractor.Unreachable {
					t.Fatalf("Javareach enrich failed, expected %s to be reachable, but marked as unreachable", pkg.Name)
				}
			}
		}
		if pkg.Name == unreachablePkgName {
			hasUnreachableAnnotation := false
			for _, annotation := range pkg.Annotations {
				if annotation == extractor.Unreachable {
					hasUnreachableAnnotation = true
				}
			}
			if !hasUnreachableAnnotation {
				t.Fatalf("Javareach enrich failed, expected %s to be unreachable, but marked as reachable", pkg.Name)
			}
		}
	}
}

func setupPackageIndex(names []string) []*extractor.Package {
	pkgs := []*extractor.Package{}

	for _, n := range names {
		unreachablePkg := &extractor.Package{
			Name:      unreachablePkgName,
			Version:   "1.2.3",
			PURLType:  purl.TypeMaven,
			Locations: []string{filepath.Join("testdata", n)},
			Extractor: &archive.Extractor{},
		}

		reachablePkg := &extractor.Package{
			Name:      reachablePkgName,
			Version:   "1.2.3",
			PURLType:  purl.TypeMaven,
			Locations: []string{filepath.Join("testdata", n)},
			Extractor: &archive.Extractor{},
		}

		pkgs = append(pkgs, unreachablePkg, reachablePkg)
	}

	return pkgs
}
