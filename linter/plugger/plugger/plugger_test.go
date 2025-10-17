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
