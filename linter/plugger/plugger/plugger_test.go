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
	"regexp"
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

	re := regexp.MustCompile(`MyPlugin`)
	interfaces := plugger.FindInterfaces(pkgs, re)
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

	impls := plugger.FindImplementations(pkgs, plugger.FindInterfaces(pkgs, regexp.MustCompile(`.*`)))

	// Collect implementation names for comparison
	var got []string
	for _, implsInPkg := range impls {
		for _, i := range implsInPkg {
			got = append(got, i.Obj().Name())
		}
	}

	want := []string{"PluginA", "PluginB"} // what you expect
	if diff := cmp.Diff(want, got, cmpopts.EquateEmpty()); diff != "" {
		t.Errorf("mismatch (-want +got):\n%s", diff)
	}
}

func TestFindConstructors(t *testing.T) {
	pkgs, err := packages.Load(cfg(), "testdata/basic")
	if err != nil {
		t.Fatal(err)
	}

	implementations := plugger.FindImplementations(
		pkgs, plugger.FindInterfaces(pkgs, regexp.MustCompile(`.*`)),
	)
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

	ctrs := plugger.FindConstructors(
		pkgs, plugger.FindImplementations(
			pkgs, plugger.FindInterfaces(pkgs, regexp.MustCompile(`.*`)),
		),
	)

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

func TestNolintRule(t *testing.T) {
	pkgs, err := packages.Load(cfg(), "testdata/basic", "testdata/nolint")
	if err != nil {
		t.Fatal(err)
	}

	impls := plugger.FindImplementations(pkgs, plugger.FindInterfaces(pkgs, regexp.MustCompile(`.*`)))

	// Collect implementation names for comparison
	var got []string
	for _, implsInPkg := range impls {
		for _, i := range implsInPkg {
			got = append(got, i.Obj().Name())
		}
	}

	want := []string{"PluginA", "PluginB"} // what you expect
	if diff := cmp.Diff(want, got, cmpopts.EquateEmpty()); diff != "" {
		t.Errorf("mismatch (-want +got):\n%s", diff)
	}
}
