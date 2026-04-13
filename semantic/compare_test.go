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

package semantic_test

import (
	"bufio"
	"errors"
	"os"
	"strings"
	"testing"

	"github.com/google/osv-scalibr/semantic"
)

func expectedResult(t *testing.T, comparator string) int {
	t.Helper()

	switch comparator {
	case "<":
		return -1
	case "=":
		return 0
	case ">":
		return +1
	default:
		t.Fatalf("unknown comparator %s", comparator)

		return -999
	}
}

func compareWord(t *testing.T, result int) string {
	t.Helper()

	switch result {
	case 1:
		return "greater than"
	case 0:
		return "equal to"
	case -1:
		return "less than"
	default:
		t.Fatalf("Unexpected compare result: %d\n", result)

		return ""
	}
}

func runAgainstEcosystemFixture(t *testing.T, ecosystem string, filename string) {
	t.Helper()

	file, err := os.Open("testdata/" + filename)
	if err != nil {
		t.Fatalf("Failed to read fixture file: %v", err)
	}

	defer file.Close()

	scanner := bufio.NewScanner(file)

	total := 0
	failed := 0

	for scanner.Scan() {
		line := scanner.Text()

		if line == "" ||
			strings.HasPrefix(line, "# ") ||
			strings.HasPrefix(line, "// ") {
			continue
		}

		total++
		pieces := strings.Split(line, " ")

		if len(pieces) != 3 {
			t.Fatalf(`incorrect number of peices in fixture "%s" (got %d)`, line, len(pieces))
		}

		result := expectEcosystemCompareResult(t, ecosystem, pieces[0], pieces[1], pieces[2])

		if !result {
			failed++
		}
	}

	if failed > 0 {
		t.Errorf("%d of %d failed", failed, total)
	}

	if err = scanner.Err(); err != nil {
		t.Fatal(err)
	}
}

func parseAsVersion(t *testing.T, str string, ecosystem string) semantic.Version {
	t.Helper()

	v, err := semantic.Parse(str, ecosystem)

	if err != nil {
		t.Fatalf("failed to parse version '%s' as ecosystem '%s': %v", str, ecosystem, err)
	}

	return v
}

func expectCompareResult(
	t *testing.T,
	ecosystem string,
	a string,
	b string,
	expectedResult int,
) bool {
	t.Helper()

	v := parseAsVersion(t, a, ecosystem)

	actualResult, err := v.CompareStr(b)

	if err != nil {
		t.Fatalf("failed to compare versions: %v", err)
	}

	if actualResult != expectedResult {
		t.Errorf(
			"Expected %s to be %s %s, but it was %s",
			a,
			compareWord(t, expectedResult),
			b,
			compareWord(t, actualResult),
		)

		return false
	}

	return true
}

func expectEcosystemCompareResult(
	t *testing.T,
	ecosystem string,
	a string,
	c string,
	b string,
) (success bool) {
	t.Helper()

	success = success || expectCompareResult(t,
		ecosystem, a, b,
		+expectedResult(t, c),
	)

	success = success && expectCompareResult(t,
		ecosystem, b, a,
		-expectedResult(t, c),
	)

	return success
}

func TestVersion_Compare_Ecosystems(t *testing.T) {
	tests := []struct {
		name string
		file string
	}{
		{
			name: "npm",
			file: "semver-versions.txt",
		},
		{
			name: "crates.io",
			file: "semver-versions.txt",
		},
		{
			name: "RubyGems",
			file: "rubygems-versions.txt",
		},
		{
			name: "RubyGems",
			file: "rubygems-versions-generated.txt",
		},
		{
			name: "NuGet",
			file: "nuget-versions.txt",
		},
		{
			name: "Packagist",
			file: "packagist-versions.txt",
		},
		{
			name: "Packagist",
			file: "packagist-versions-generated.txt",
		},
		{
			name: "Go",
			file: "semver-versions.txt",
		},
		{
			name: "Hex",
			file: "semver-versions.txt",
		},
		{
			name: "Maven",
			file: "maven-versions.txt",
		},
		{
			name: "Maven",
			file: "maven-versions-generated.txt",
		},
		{
			name: "PyPI",
			file: "pypi-versions.txt",
		},
		{
			name: "PyPI",
			file: "pypi-versions-generated.txt",
		},
		{
			name: "Debian",
			file: "debian-versions.txt",
		},
		{
			name: "Debian",
			file: "debian-versions-generated.txt",
		},
		{
			name: "CRAN",
			file: "cran-versions.txt",
		},
		{
			name: "CRAN",
			file: "cran-versions-generated.txt",
		},
		{
			name: "Alpine",
			file: "alpine-versions.txt",
		},
		{
			name: "Alpine",
			file: "alpine-versions-generated.txt",
		},
		{
			name: "Red Hat",
			file: "redhat-versions.txt",
		},
		{
			name: "Hackage",
			file: "hackage-versions.txt",
		},
		{
			name: "Pub",
			file: "pub-versions.txt",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			runAgainstEcosystemFixture(t, tt.name, tt.file)
		})
	}
}

func TestVersion_Compare_Debian_InvalidVersion(t *testing.T) {
	v := parseAsVersion(t, "1.2.3", "Debian")

	_, err := v.CompareStr("1.2.3-not-a-debian:version!@#$")

	if err == nil {
		t.Fatalf("expected error comparing invalid version")
	}

	if !errors.Is(err, semantic.ErrInvalidVersion) {
		t.Errorf("expected ErrInvalidVersion, got '%v'", err)
	}
}
