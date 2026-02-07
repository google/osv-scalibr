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

package plugger_test

import (
	"fmt"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/google/osv-scalibr/linter/plugger/plugger"
	"golang.org/x/tools/go/packages"
)

var ignoreOrder = cmpopts.SortSlices(func(a, b string) bool { return a < b })

func cfg() *packages.Config {
	cfg := plugger.Config
	cfg.Dir = "./testdata"
	return cfg
}

func TestFindInterfaces(t *testing.T) {
	pkgs, err := packages.Load(cfg(), "testdata/basic")
	if err != nil {
		t.Fatal(err)
	}

	interfaces := plugger.FindInterfaces(pkgs, []string{"testdata/basic.MyPlugin"})
	var got []string
	for _, iface := range interfaces {
		got = append(got, iface.String())
	}

	want := []string{"testdata/basic.MyPlugin"}
	if diff := cmp.Diff(want, got, ignoreOrder); diff != "" {
		t.Errorf("mismatch (-want +got):\n%s", diff)
	}
}

func TestFindConstructors(t *testing.T) {
	pkgs, err := packages.Load(cfg(), "testdata/basic")
	if err != nil {
		t.Fatal(err)
	}

	interfaces := plugger.FindInterfaces(pkgs, []string{"testdata/basic.MyPlugin"})
	ctrs := plugger.FindConstructors(pkgs, interfaces)
	var got []string
	for _, ctr := range ctrs {
		got = append(got, ctr.Fun.Name.String())
	}

	want := []string{
		"NewPluginA",
		"NewPluginB",
	}

	if diff := cmp.Diff(want, got, ignoreOrder); diff != "" {
		t.Errorf("mismatch (-want +got):\n%s", diff)
	}
}

func TestFindUsages(t *testing.T) {
	// Load the mock packages
	pkgs, err := packages.Load(cfg(), "testdata/basic", "testdata/usage")
	if err != nil {
		t.Fatal(err)
	}

	interfaces := plugger.FindInterfaces(pkgs, []string{"testdata/basic.MyPlugin"})
	ctrs := plugger.FindConstructors(pkgs, interfaces)

	usages := plugger.FindUsages(pkgs, ctrs)
	var got []string
	for _, u := range usages {
		got = append(got, u.Fun.Name.String())
	}

	// only NewPluginA since NewPluginB is called only in tests
	want := []string{
		"NewPluginA",
	}

	if diff := cmp.Diff(want, got, ignoreOrder); diff != "" {
		t.Errorf("mismatch (-want +got):\n%s", diff)
	}
}

func TestAliases(t *testing.T) {
	// Load the mock packages
	pkgs, err := packages.Load(cfg(), "testdata/alias", "testdata/basic")
	if err != nil {
		t.Fatal(err)
	}

	interfaces := plugger.FindInterfaces(pkgs, []string{"testdata/basic.MyPlugin"})
	ctrs := plugger.FindConstructors(pkgs, interfaces)

	got := map[string]string{}
	for _, ctr := range ctrs {
		got[ctr.String()] = fmt.Sprint(ctr.Aliases)
	}

	// these NewAlias and NewDefault should be aliases of all of them since
	// they contain the pkg.Name and "Default" suffixes
	//
	// Note: usually when a function like New or NewDefault or NewPkgName is returned
	// the return type is the only public type returned by the pkg, otherwise it will
	// have a more specific name
	want := map[string]string{
		"alias.NewDefault":   "[alias.NewDetector alias.NewValidator]",
		"alias.NewDetector":  "[alias.NewDefault]",
		"alias.NewValidator": "[alias.NewDefault]",
		"basic.NewPluginA":   "[]",
		"basic.NewPluginB":   "[]",
	}

	if diff := cmp.Diff(want, got, ignoreOrder); diff != "" {
		t.Errorf("mismatch (-want +got):\n%s", diff)
	}
}

func TestPkgNoLintRule(t *testing.T) {
	pkgs, err := packages.Load(cfg(), "testdata/basic", "testdata/nolint/pkg")
	if err != nil {
		t.Fatal(err)
	}

	pkgs = plugger.FilterNoLintPackages(pkgs)

	interfaces := plugger.FindInterfaces(pkgs, []string{"testdata/basic.MyPlugin"})
	ctrs := plugger.FindConstructors(pkgs, interfaces)

	var got []string
	for _, ctr := range ctrs {
		got = append(got, ctr.Fun.Name.String())
	}

	want := []string{
		"NewPluginA",
		"NewPluginB",
	}

	if diff := cmp.Diff(want, got, ignoreOrder); diff != "" {
		t.Errorf("mismatch (-want +got):\n%s", diff)
	}
}

func TestFunNoLintRule(t *testing.T) {
	pkgs, err := packages.Load(cfg(), "testdata/basic", "testdata/nolint/fun")
	if err != nil {
		t.Fatal(err)
	}

	interfaces := plugger.FindInterfaces(pkgs, []string{"testdata/basic.MyPlugin"})
	ctrs := plugger.FindConstructors(pkgs, interfaces)

	var got []string
	for _, ctr := range ctrs {
		got = append(got, ctr.Fun.Name.String())
	}

	want := []string{
		"NewPluginA",
		"NewPluginB",
		"NewPlugin",
	}

	if diff := cmp.Diff(want, got, ignoreOrder); diff != "" {
		t.Errorf("mismatch (-want +got):\n%s", diff)
	}
}

func TestExternal(t *testing.T) {
	pkgs, err := packages.Load(cfg(), "testdata/basic", "testdata/external")
	if err != nil {
		t.Fatal(err)
	}

	interfaces := plugger.FindInterfaces(pkgs, []string{"testdata/basic.MyPlugin"})
	ctrs := plugger.FindConstructors(pkgs, interfaces)

	var got []string
	for _, ctr := range ctrs {
		got = append(got, ctr.Fun.Name.String())
	}

	want := []string{
		"NewPluginA",
		"NewPluginB",
		"NewPluginExternalWithoutConcrete",
		"NewPluginExternal",
	}

	if diff := cmp.Diff(want, got, ignoreOrder); diff != "" {
		t.Errorf("mismatch (-want +got):\n%s", diff)
	}
}

func TestGeneric(t *testing.T) {
	pkgs, err := packages.Load(cfg(), "testdata/generic")
	if err != nil {
		t.Fatal(err)
	}

	interfaces := plugger.FindInterfaces(pkgs, []string{"testdata/generic.Validator"})
	ctrs := plugger.FindConstructors(pkgs, interfaces)

	var got []string
	for _, ctr := range ctrs {
		got = append(got, ctr.Fun.Name.String())
	}

	want := []string{"NewValidator"}

	if diff := cmp.Diff(want, got, ignoreOrder); diff != "" {
		t.Errorf("mismatch (-want +got):\n%s", diff)
	}
}
