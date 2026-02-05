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

package osvlocal

import (
	"errors"
	"net/http"
	"os"
	"path"
	"sort"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/osv-scalibr/enricher/vulnmatch/osvlocal/internal/fakeserver"
	"github.com/google/osv-scalibr/extractor"
	scalibrversion "github.com/google/osv-scalibr/version"
	osvpb "github.com/ossf/osv-schema/bindings/go/osvschema"
	"google.golang.org/protobuf/testing/protocmp"
)

// createTestDir makes a temporary directory for use in testing that involves
// writing and reading files from disk, which is automatically cleaned up
// when testing finishes
func createTestDir(t *testing.T) string {
	t.Helper()

	//nolint:usetesting // we need to customize the directory name to replace in snapshots
	p, err := os.MkdirTemp("", "osv-scanner-test-*")
	if err != nil {
		t.Fatalf("could not create test directory: %v", err)
	}

	// ensure the test directory is removed when we're done testing
	t.Cleanup(func() {
		_ = os.RemoveAll(p)
	})

	return p
}

const userAgent = "osv-scanner_scan/" + scalibrversion.ScannerVersion

func expectDBToHaveOSVs(
	t *testing.T,
	db *zipDB,
	expect []*osvpb.Vulnerability,
) {
	t.Helper()

	vulns := db.Vulnerabilities

	sort.Slice(vulns, func(i, j int) bool {
		return vulns[i].GetId() < vulns[j].GetId()
	})
	sort.Slice(expect, func(i, j int) bool {
		return expect[i].GetId() < expect[j].GetId()
	})

	if diff := cmp.Diff(expect, vulns, protocmp.Transform()); diff != "" {
		t.Errorf("db is missing some vulnerabilities (-want +got):\n%s", diff)
	}
}

func cacheWrite(t *testing.T, storedAt string, cache []byte) {
	t.Helper()

	err := os.MkdirAll(path.Dir(storedAt), 0750)

	if err == nil {
		//nolint:gosec // being world readable is fine
		err = os.WriteFile(storedAt, cache, 0644)
	}

	if err != nil {
		t.Errorf("unexpected error with cache: %v", err)
	}
}

func cacheWriteBad(t *testing.T, storedAt string, contents string) {
	t.Helper()

	err := os.MkdirAll(path.Dir(storedAt), 0750)

	if err == nil {
		//nolint:gosec // being world readable is fine
		err = os.WriteFile(storedAt, []byte(contents), 0644)
	}

	if err != nil {
		t.Errorf("unexpected error with cache: %v", err)
	}
}

//nolint:unparam // name might get changed at some point
func determineStoredAtPath(dbBasePath, name string) string {
	return path.Join(dbBasePath, name, "all.zip")
}

func TestNewZippedDB_Offline_WithoutCache(t *testing.T) {
	testDir := createTestDir(t)

	ts := fakeserver.CreateZipServer(t, func(_ http.ResponseWriter, _ *http.Request) {
		t.Errorf("a server request was made when running offline")
	})

	_, err := newZippedDB(t.Context(), testDir, "my-db", ts.URL, userAgent, true, nil)

	if !errors.Is(err, errOfflineDatabaseNotFound) {
		t.Errorf("expected \"%v\" error but got \"%v\"", errOfflineDatabaseNotFound, err)
	}
}

func TestNewZippedDB_Offline_WithCache(t *testing.T) {
	osvs := []*osvpb.Vulnerability{
		{Id: "GHSA-1"},
		{Id: "GHSA-2"},
		{Id: "GHSA-3"},
		{Id: "GHSA-4"},
		{Id: "GHSA-5"},
	}

	testDir := createTestDir(t)

	ts := fakeserver.CreateZipServer(t, func(_ http.ResponseWriter, _ *http.Request) {
		t.Errorf("a server request was made when running offline")
	})

	cacheWrite(t, determineStoredAtPath(testDir, "my-db"), fakeserver.ZipOSVs(t, map[string]*osvpb.Vulnerability{
		"GHSA-1.json": {Id: "GHSA-1"},
		"GHSA-2.json": {Id: "GHSA-2"},
		"GHSA-3.json": {Id: "GHSA-3"},
		"GHSA-4.json": {Id: "GHSA-4"},
		"GHSA-5.json": {Id: "GHSA-5"},
	}))

	db, err := newZippedDB(t.Context(), testDir, "my-db", ts.URL, userAgent, true, nil)

	if err != nil {
		t.Fatalf("unexpected error \"%v\"", err)
	}

	expectDBToHaveOSVs(t, db, osvs)
}

func TestNewZippedDB_BadZip(t *testing.T) {
	testDir := createTestDir(t)

	ts := fakeserver.CreateZipServer(t, func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("this is not a zip"))
	})

	_, err := newZippedDB(t.Context(), testDir, "my-db", ts.URL, userAgent, false, nil)

	if err == nil {
		t.Errorf("expected an error but did not get one")
	}
}

func TestNewZippedDB_UnsupportedProtocol(t *testing.T) {
	testDir := createTestDir(t)

	_, err := newZippedDB(t.Context(), testDir, "my-db", "file://hello-world", userAgent, false, nil)

	if err == nil {
		t.Errorf("expected an error but did not get one")
	}
}

func TestNewZippedDB_Online_WithoutCache(t *testing.T) {
	osvs := []*osvpb.Vulnerability{
		{Id: "GHSA-1"},
		{Id: "GHSA-2"},
		{Id: "GHSA-3"},
		{Id: "GHSA-4"},
		{Id: "GHSA-5"},
	}

	testDir := createTestDir(t)

	ts := fakeserver.CreateZipServer(t, func(w http.ResponseWriter, _ *http.Request) {
		_, _ = fakeserver.WriteOSVsZip(t, w, map[string]*osvpb.Vulnerability{
			"GHSA-1.json": {Id: "GHSA-1"},
			"GHSA-2.json": {Id: "GHSA-2"},
			"GHSA-3.json": {Id: "GHSA-3"},
			"GHSA-4.json": {Id: "GHSA-4"},
			"GHSA-5.json": {Id: "GHSA-5"},
		})
	})

	db, err := newZippedDB(t.Context(), testDir, "my-db", ts.URL, userAgent, false, nil)

	if err != nil {
		t.Fatalf("unexpected error \"%v\"", err)
	}

	expectDBToHaveOSVs(t, db, osvs)
}

func TestNewZippedDB_Online_WithoutCacheAndNoHashHeader(t *testing.T) {
	osvs := []*osvpb.Vulnerability{
		{Id: "GHSA-1"},
		{Id: "GHSA-2"},
		{Id: "GHSA-3"},
		{Id: "GHSA-4"},
		{Id: "GHSA-5"},
	}

	testDir := createTestDir(t)

	ts := fakeserver.CreateZipServer(t, func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write(fakeserver.ZipOSVs(t, map[string]*osvpb.Vulnerability{
			"GHSA-1.json": {Id: "GHSA-1"},
			"GHSA-2.json": {Id: "GHSA-2"},
			"GHSA-3.json": {Id: "GHSA-3"},
			"GHSA-4.json": {Id: "GHSA-4"},
			"GHSA-5.json": {Id: "GHSA-5"},
		}))
	})

	db, err := newZippedDB(t.Context(), testDir, "my-db", ts.URL, userAgent, false, nil)

	if err != nil {
		t.Fatalf("unexpected error \"%v\"", err)
	}

	expectDBToHaveOSVs(t, db, osvs)
}

func TestNewZippedDB_Online_WithSameCache(t *testing.T) {
	osvs := []*osvpb.Vulnerability{
		{Id: "GHSA-1"},
		{Id: "GHSA-2"},
		{Id: "GHSA-3"},
	}

	testDir := createTestDir(t)

	cache := fakeserver.ZipOSVs(t, map[string]*osvpb.Vulnerability{
		"GHSA-1.json": {Id: "GHSA-1"},
		"GHSA-2.json": {Id: "GHSA-2"},
		"GHSA-3.json": {Id: "GHSA-3"},
	})

	ts := fakeserver.CreateZipServer(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodHead {
			t.Errorf("unexpected %s request", r.Method)
		}

		w.Header().Add("X-Goog-Hash", "crc32c="+fakeserver.ComputeCRC32CHash(t, cache))

		_, _ = w.Write(cache)
	})

	cacheWrite(t, determineStoredAtPath(testDir, "my-db"), cache)

	db, err := newZippedDB(t.Context(), testDir, "my-db", ts.URL, userAgent, false, nil)

	if err != nil {
		t.Fatalf("unexpected error \"%v\"", err)
	}

	expectDBToHaveOSVs(t, db, osvs)
}

func TestNewZippedDB_Online_WithDifferentCache(t *testing.T) {
	osvs := []*osvpb.Vulnerability{
		{Id: "GHSA-1"},
		{Id: "GHSA-2"},
		{Id: "GHSA-3"},
		{Id: "GHSA-4"},
		{Id: "GHSA-5"},
	}

	testDir := createTestDir(t)

	ts := fakeserver.CreateZipServer(t, func(w http.ResponseWriter, _ *http.Request) {
		_, _ = fakeserver.WriteOSVsZip(t, w, map[string]*osvpb.Vulnerability{
			"GHSA-1.json": {Id: "GHSA-1"},
			"GHSA-2.json": {Id: "GHSA-2"},
			"GHSA-3.json": {Id: "GHSA-3"},
			"GHSA-4.json": {Id: "GHSA-4"},
			"GHSA-5.json": {Id: "GHSA-5"},
		})
	})

	cacheWrite(t, determineStoredAtPath(testDir, "my-db"), fakeserver.ZipOSVs(t, map[string]*osvpb.Vulnerability{
		"GHSA-1.json": {Id: "GHSA-1"},
		"GHSA-2.json": {Id: "GHSA-2"},
		"GHSA-3.json": {Id: "GHSA-3"},
	}))

	db, err := newZippedDB(t.Context(), testDir, "my-db", ts.URL, userAgent, false, nil)

	if err != nil {
		t.Fatalf("unexpected error \"%v\"", err)
	}

	expectDBToHaveOSVs(t, db, osvs)
}

func TestNewZippedDB_Online_WithCacheButNoHashHeader(t *testing.T) {
	testDir := createTestDir(t)

	ts := fakeserver.CreateZipServer(t, func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write(fakeserver.ZipOSVs(t, map[string]*osvpb.Vulnerability{
			"GHSA-1.json": {Id: "GHSA-1"},
			"GHSA-2.json": {Id: "GHSA-2"},
			"GHSA-3.json": {Id: "GHSA-3"},
			"GHSA-4.json": {Id: "GHSA-4"},
			"GHSA-5.json": {Id: "GHSA-5"},
		}))
	})

	cacheWrite(t, determineStoredAtPath(testDir, "my-db"), fakeserver.ZipOSVs(t, map[string]*osvpb.Vulnerability{
		"GHSA-1.json": {Id: "GHSA-1"},
		"GHSA-2.json": {Id: "GHSA-2"},
		"GHSA-3.json": {Id: "GHSA-3"},
	}))

	_, err := newZippedDB(t.Context(), testDir, "my-db", ts.URL, userAgent, false, nil)

	if err == nil {
		t.Errorf("expected an error but did not get one")
	}
}

func TestNewZippedDB_Online_WithBadCache(t *testing.T) {
	osvs := []*osvpb.Vulnerability{
		{Id: "GHSA-1"},
		{Id: "GHSA-2"},
		{Id: "GHSA-3"},
	}

	testDir := createTestDir(t)

	ts := fakeserver.CreateZipServer(t, func(w http.ResponseWriter, _ *http.Request) {
		_, _ = fakeserver.WriteOSVsZip(t, w, map[string]*osvpb.Vulnerability{
			"GHSA-1.json": {Id: "GHSA-1"},
			"GHSA-2.json": {Id: "GHSA-2"},
			"GHSA-3.json": {Id: "GHSA-3"},
		})
	})

	cacheWriteBad(t, determineStoredAtPath(testDir, "my-db"), "this is not json!")

	db, err := newZippedDB(t.Context(), testDir, "my-db", ts.URL, userAgent, false, nil)

	if err != nil {
		t.Fatalf("unexpected error \"%v\"", err)
	}

	expectDBToHaveOSVs(t, db, osvs)
}

func TestNewZippedDB_FileChecks(t *testing.T) {
	osvs := []*osvpb.Vulnerability{{Id: "GHSA-1234"}, {Id: "GHSA-4321"}}

	testDir := createTestDir(t)

	ts := fakeserver.CreateZipServer(t, func(w http.ResponseWriter, _ *http.Request) {
		_, _ = fakeserver.WriteOSVsZip(t, w, map[string]*osvpb.Vulnerability{
			"file.json": {Id: "GHSA-1234"},
			// only files with .json suffix should be loaded
			"file.yaml": {Id: "GHSA-5678"},
			// (no longer) special case for the GH security database
			"advisory-database-main/advisories/unreviewed/file.json": {Id: "GHSA-4321"},
		})
	})

	db, err := newZippedDB(t.Context(), testDir, "my-db", ts.URL, userAgent, false, nil)

	if err != nil {
		t.Fatalf("unexpected error \"%v\"", err)
	}

	expectDBToHaveOSVs(t, db, osvs)
}

func TestNewZippedDB_WithSpecificPackages(t *testing.T) {
	testDir := createTestDir(t)

	ts := fakeserver.CreateZipServer(t, func(w http.ResponseWriter, _ *http.Request) {
		_, _ = fakeserver.WriteOSVsZip(t, w, map[string]*osvpb.Vulnerability{
			"GHSA-1.json": {
				Id:       "GHSA-1",
				Affected: []*osvpb.Affected{},
			},
			"GHSA-2.json": {
				Id: "GHSA-2",
				Affected: []*osvpb.Affected{
					{Package: &osvpb.Package{Name: "pkg-1"}},
				},
			},
			"GHSA-3.json": {
				Id: "GHSA-3",
			},
			"GHSA-4.json": {
				Id: "GHSA-4",
				Affected: []*osvpb.Affected{
					{Package: &osvpb.Package{Name: "pkg-2"}},
				},
			},
			"GHSA-5.json": {
				Id: "GHSA-5",
				Affected: []*osvpb.Affected{
					{Package: &osvpb.Package{Name: "pkg-2"}},
					{Package: &osvpb.Package{Name: "pkg-1"}},
				},
			},
			"GHSA-6.json": {
				Id: "GHSA-6",
				Affected: []*osvpb.Affected{
					{Package: &osvpb.Package{Name: "pkg-3"}},
					{Package: &osvpb.Package{Name: "pkg-2"}},
				},
			},
		})
	})

	db, err := newZippedDB(
		t.Context(),
		testDir,
		"my-db",
		ts.URL,
		userAgent,
		false,
		[]*extractor.Package{{Name: "pkg-1"}, {Name: "pkg-3"}},
	)

	if err != nil {
		t.Fatalf("unexpected error \"%v\"", err)
	}

	expectDBToHaveOSVs(t, db, []*osvpb.Vulnerability{
		{
			Id: "GHSA-2",
			Affected: []*osvpb.Affected{
				{Package: &osvpb.Package{Name: "pkg-1"}},
			},
		},
		{
			Id: "GHSA-5",
			Affected: []*osvpb.Affected{
				{Package: &osvpb.Package{Name: "pkg-2"}},
				{Package: &osvpb.Package{Name: "pkg-1"}},
			},
		},
		{
			Id: "GHSA-6",
			Affected: []*osvpb.Affected{
				{Package: &osvpb.Package{Name: "pkg-3"}},
				{Package: &osvpb.Package{Name: "pkg-2"}},
			},
		},
	})
}
