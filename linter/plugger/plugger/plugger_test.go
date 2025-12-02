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

package plugger_test

import (
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/google/osv-scalibr/linter/plugger/plugger"
	"golang.org/x/tools/go/packages"
)

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
	if diff := cmp.Diff(want, got, cmpopts.EquateEmpty()); diff != "" {
		t.Errorf("mismatch (-want +got):\n%s", diff)
	}
}

func TestFindImplementations(t *testing.T) {
	pkgs, err := packages.Load(cfg(), "testdata/basic")
	if err != nil {
		t.Fatal(err)
	}

	impls := plugger.FindImplementations(pkgs, plugger.FindInterfaces(pkgs, []string{"testdata/basic.MyPlugin"}))

	// Collect implementation names for comparison
	var got []string
	for _, impl := range impls {
		got = append(got, impl.Obj().Name())
	}

	want := []string{"MyPlugin", "PluginA", "PluginB"}
	if diff := cmp.Diff(want, got, cmpopts.EquateEmpty()); diff != "" {
		t.Errorf("mismatch (-want +got):\n%s", diff)
	}
}

func TestFindImplementationsWithGeneric(t *testing.T) {
	pkgs, err := packages.Load(cfg(), "testdata/generic")
	if err != nil {
		t.Fatal(err)
	}

	interfaces := plugger.FindInterfaces(pkgs, []string{"testdata/generic.Validator", "testdata/generic.IComplex"})
	if len(interfaces) != 2 {
		t.Errorf("expected 2 interface, found %d", len(interfaces))
	}

	impls := plugger.FindImplementations(pkgs, interfaces)

	// Collect implementation names for comparison
	var got []string
	for _, impl := range impls {
		got = append(got, impl.Obj().Name())
	}

	want := []string{"Validator", "TestPointer", "Test", "TestAnotherType", "IComplex", "Complex"}
	if diff := cmp.Diff(want, got, cmpopts.EquateEmpty()); diff != "" {
		t.Errorf("mismatch (-want +got):\n%s", diff)
	}
}

func TestFindConstructors(t *testing.T) {
	pkgs, err := packages.Load(cfg(), "testdata/basic")
	if err != nil {
		t.Fatal(err)
	}

	interfaces := plugger.FindInterfaces(pkgs, []string{"testdata/basic.MyPlugin"})
	implementations := plugger.FindImplementations(pkgs, interfaces)
	ctrs := plugger.FindConstructors(pkgs, implementations)
	var got []string
	for _, ctr := range ctrs {
		got = append(got, ctr.Fun.Name.String())
	}

	want := []string{
		"NewPluginA",
		"NewPluginB",
	}

	if diff := cmp.Diff(want, got, cmpopts.EquateEmpty()); diff != "" {
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
	implementations := plugger.FindImplementations(pkgs, interfaces)
	ctrs := plugger.FindConstructors(pkgs, implementations)

	usages := plugger.FindUsages(pkgs, ctrs)
	var got []string
	for _, u := range usages {
		got = append(got, u.Fun.Name.String())
	}

	// only NewPluginA since NewPluginB is called only in tests
	want := []string{
		"NewPluginA",
	}

	if diff := cmp.Diff(want, got, cmpopts.EquateEmpty()); diff != "" {
		t.Errorf("mismatch (-want +got):\n%s", diff)
	}
}

func TestStructNoLintRule(t *testing.T) {
	pkgs, err := packages.Load(cfg(), "testdata/basic", "testdata/nolint/plugin")
	if err != nil {
		t.Fatal(err)
	}

	impls := plugger.FindImplementations(pkgs, plugger.FindInterfaces(pkgs, []string{"testdata/basic.MyPlugin"}))

	// Collect implementation names for comparison
	var got []string
	for _, impl := range impls {
		got = append(got, impl.Obj().Name())
	}

	want := []string{"MyPlugin", "PluginA", "PluginB", "PluginNotUsedToLint"}
	if diff := cmp.Diff(want, got, cmpopts.EquateEmpty()); diff != "" {
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
	implementations := plugger.FindImplementations(pkgs, interfaces)
	ctrs := plugger.FindConstructors(pkgs, implementations)

	var got []string
	for _, ctr := range ctrs {
		got = append(got, ctr.Fun.Name.String())
	}

	want := []string{
		"NewPluginA",
		"NewPluginB",
	}

	if diff := cmp.Diff(want, got, cmpopts.EquateEmpty()); diff != "" {
		t.Errorf("mismatch (-want +got):\n%s", diff)
	}
}

func TestFunNoLintRule(t *testing.T) {
	pkgs, err := packages.Load(cfg(), "testdata/basic", "testdata/nolint/fun")
	if err != nil {
		t.Fatal(err)
	}

	interfaces := plugger.FindInterfaces(pkgs, []string{"testdata/basic.MyPlugin"})
	implementations := plugger.FindImplementations(pkgs, interfaces)
	ctrs := plugger.FindConstructors(pkgs, implementations)

	var got []string
	for _, ctr := range ctrs {
		got = append(got, ctr.Fun.Name.String())
	}

	want := []string{
		"NewPluginA",
		"NewPluginB",
		"NewPlugin",
	}

	if diff := cmp.Diff(want, got, cmpopts.EquateEmpty()); diff != "" {
		t.Errorf("mismatch (-want +got):\n%s", diff)
	}
}

func TestExternal(t *testing.T) {
	pkgs, err := packages.Load(cfg(), "testdata/basic", "testdata/external")
	if err != nil {
		t.Fatal(err)
	}

	interfaces := plugger.FindInterfaces(pkgs, []string{"testdata/basic.MyPlugin"})
	implementations := plugger.FindImplementations(pkgs, interfaces)
	ctrs := plugger.FindConstructors(pkgs, implementations)

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

	if diff := cmp.Diff(want, got, cmpopts.EquateEmpty()); diff != "" {
		t.Errorf("mismatch (-want +got):\n%s", diff)
	}
}

func TestGenericReturnType(t *testing.T) {
	pkgs, err := packages.Load(cfg(), "testdata/generic/genericreturn")
	if err != nil {
		t.Fatal(err)
	}

	interfaces := plugger.FindInterfaces(pkgs, []string{"testdata/generic/genericreturn.Validator"})
	implementations := plugger.FindImplementations(pkgs, interfaces)
	ctrs := plugger.FindConstructors(pkgs, implementations)

	var got []string
	for _, ctr := range ctrs {
		got = append(got, ctr.Fun.Name.String())
	}

	want := []string{"NewValidator"}

	if diff := cmp.Diff(want, got, cmpopts.EquateEmpty()); diff != "" {
		t.Errorf("mismatch (-want +got):\n%s", diff)
	}
}
