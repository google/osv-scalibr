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

package depgraph_test

import (
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/osv-scalibr/extractor"
	"github.com/google/osv-scalibr/extractor/filesystem/internal/depgraph"
)

type testIDGenerator struct{ counter int }

func (g *testIDGenerator) GenerateID(name string) (string, error) {
	if strings.HasPrefix(name, "fail") {
		return "", errors.New("no ID for " + name)
	}
	g.counter++
	return fmt.Sprintf("id-%s-%d", name, g.counter), nil
}

func setTestIDGenerator(t *testing.T) {
	t.Helper()
	extractor.SetIDGenerator(&testIDGenerator{})
	t.Cleanup(func() { extractor.SetIDGenerator(&extractor.RandomIDGenerator{}) })
}

func TestEdgesByName(t *testing.T) {
	a := &extractor.Package{Name: "A", Version: "1"}
	b := &extractor.Package{Name: "b", Version: "1"}
	b2 := &extractor.Package{Name: "b", Version: "2"}
	packages := []*extractor.Package{a, b, b2}
	deps := [][]string{{"B", "missing"}, {"b"}, {"a"}}

	got := depgraph.EdgesByName(packages,
		func(i int) []string { return deps[i] },
		strings.ToLower)

	want := []depgraph.Edge{
		{Parent: a, Child: b},
		{Parent: a, Child: b2},
		{Parent: b, Child: b2},
		{Parent: b2, Child: a},
	}
	if diff := cmp.Diff(want, got, cmp.Comparer(func(x, y *extractor.Package) bool { return x == y })); diff != "" {
		t.Errorf("EdgesByName() diff (-want +got):\n%s", diff)
	}
}

func TestEdgesByName_ExactMatchWithNilNormalize(t *testing.T) {
	a := &extractor.Package{Name: "A"}
	b := &extractor.Package{Name: "b"}
	packages := []*extractor.Package{a, b}
	deps := [][]string{{"B"}, {"A"}}

	got := depgraph.EdgesByName(packages, func(i int) []string { return deps[i] }, nil)

	want := []depgraph.Edge{{Parent: b, Child: a}}
	if diff := cmp.Diff(want, got, cmp.Comparer(func(x, y *extractor.Package) bool { return x == y })); diff != "" {
		t.Errorf("EdgesByName() diff (-want +got):\n%s", diff)
	}
}

func TestApplyEdges(t *testing.T) {
	setTestIDGenerator(t)
	a := &extractor.Package{Name: "a"}
	b := &extractor.Package{Name: "b"}
	failing := &extractor.Package{Name: "fail-pkg"}
	packages := []*extractor.Package{a, b, failing}

	err := depgraph.ApplyEdges(packages, []depgraph.Edge{
		{Parent: a, Child: b},
		{Parent: nil, Child: a},
		{Parent: failing, Child: b},
		{Parent: a, Child: failing},
	})

	if err == nil {
		t.Error("ApplyEdges() expected error for fail-pkg, got nil")
	}
	if a.ID != "id-a-1" || b.ID != "id-b-2" {
		t.Errorf("ApplyEdges() IDs = %q, %q, want id-a-1, id-b-2", a.ID, b.ID)
	}
	if diff := cmp.Diff(map[string]bool{"root": true}, a.ParentIDs); diff != "" {
		t.Errorf("a.ParentIDs diff (-want +got):\n%s", diff)
	}
	if diff := cmp.Diff(map[string]bool{"id-a-1": true}, b.ParentIDs); diff != "" {
		t.Errorf("b.ParentIDs diff (-want +got):\n%s", diff)
	}
	if failing.ParentIDs != nil {
		t.Errorf("failing.ParentIDs = %v, want nil", failing.ParentIDs)
	}
}
