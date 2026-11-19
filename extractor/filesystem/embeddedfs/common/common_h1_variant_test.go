// Copyright 2026 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0

// PoC test for H1 variant of CVE-2025-5981 — Windows-only path traversal
// in the recursive embedded filesystem extractors. See the upstream report
// for full context. The current filter (post-commit b85a70dd) only rejects
// entries containing forward-slash. On GOOS=windows, filepath.Join treats
// backslash as a path separator, so an entry name like `..\evil` passes the
// filter and escapes the extraction tempdir.

package common

import (
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

// fakeDirEntry is a minimal fs.DirEntry implementation used to simulate the
// behaviour of a third-party filesystem driver (e.g. masahiro331/go-ext4-filesystem)
// returning a raw inode name with backslash bytes. ext4 inode names allow any
// byte except NUL and `/` per kernel rules, but a *raw* image crafted by an
// attacker can encode arbitrary bytes including 0x5C (`\`).
type fakeDirEntry struct {
	name string
	dir  bool
}

func (f fakeDirEntry) Name() string               { return f.name }
func (f fakeDirEntry) IsDir() bool                { return f.dir }
func (f fakeDirEntry) Type() fs.FileMode          { return 0 }
func (f fakeDirEntry) Info() (fs.FileInfo, error) { return nil, nil }

// TestH1FilterAcceptsBackslashTraversal proves that the current
// filterEntriesExt (post-patch b85a70dd) does NOT reject backslash-bearing
// names that are interpreted as parent-directory traversal on Windows.
//
// This test is platform-independent: the filter is pure string logic.
func TestH1FilterAcceptsBackslashTraversal(t *testing.T) {
	entries := []fs.DirEntry{
		fakeDirEntry{name: ".."},                      // baseline: filtered
		fakeDirEntry{name: "../evil"},                 // baseline: filtered (forward slash)
		fakeDirEntry{name: `..\evil_h1_marker.txt`},   // CANDIDATE: backslash, passes filter
		fakeDirEntry{name: `..\..\..\evil_marker.txt`}, // CANDIDATE: deeper escape
	}

	filtered := filterEntriesExt(entries)

	// Expect: only the two backslash entries survive.
	want := map[string]bool{
		`..\evil_h1_marker.txt`:      true,
		`..\..\..\evil_marker.txt`:   true,
	}
	if len(filtered) != len(want) {
		t.Fatalf("filterEntriesExt: expected %d survivors, got %d (%v)",
			len(want), len(filtered), namesOf(filtered))
	}
	for _, e := range filtered {
		if !want[e.Name()] {
			t.Errorf("unexpected entry survived filter: %q", e.Name())
		}
	}
	t.Logf("CONFIRMED: filterEntriesExt accepts %v — backslash bypasses the post-patch /-only check",
		namesOf(filtered))
}

// TestH1JoinEscapesTempdirOnWindows demonstrates the runtime traversal:
// once the malicious entry survives the filter, filepath.Join + filepath.Clean
// on Windows resolve `..` segments and the resulting destFullPath escapes
// the per-scan tempdir. On Linux this test self-skips because the OS-specific
// separator differs.
func TestH1JoinEscapesTempdirOnWindows(t *testing.T) {
	tempdir := t.TempDir()
	maliciousName := `..\evil_h1_marker_` + tsSuffix() + `.txt`

	destFullPath := filepath.Join(tempdir, maliciousName)
	cleanDst := filepath.Clean(tempdir)
	cleanJoin := filepath.Clean(destFullPath)

	t.Logf("GOOS         = %s", runtime.GOOS)
	t.Logf("separator    = %q", filepath.Separator)
	t.Logf("tempdir      = %s", cleanDst)
	t.Logf("malicious    = %q", maliciousName)
	t.Logf("destFullPath = %s", cleanJoin)

	escapes := cleanJoin != cleanDst &&
		!strings.HasPrefix(cleanJoin, cleanDst+string(filepath.Separator))

	if !escapes {
		t.Skipf("Backslash is not a separator on GOOS=%s; run this test with GOOS=windows to observe traversal. "+
			"Static analysis confirms: on Windows filepath.Join(%q, %q) -> %q which is outside the tempdir.",
			runtime.GOOS, cleanDst, maliciousName,
			windowsLikeJoin(cleanDst, maliciousName))
		return
	}

	t.Logf("CONFIRMED: destFullPath escapes the scan tempdir on this GOOS. " +
		"In ExtractAllRecursiveExt (common.go:171) os.Create(destFullPath) " +
		"would then write outside the tempdir, owned by whichever account runs scalibr.")

	// Bonus: confirm os.Create would actually attempt the write at the escape path.
	// We do NOT execute it to avoid touching the filesystem outside t.TempDir,
	// but we assert the parent directory of the escape path is NOT under tempdir.
	parentOfEscape := filepath.Dir(cleanJoin)
	if strings.HasPrefix(parentOfEscape, cleanDst) {
		t.Errorf("unexpected: parent of escape path %q is still inside tempdir %q",
			parentOfEscape, cleanDst)
	}
}

// TestH1AllThreeExtractorsShareDefect documents that the same defect class
// exists in filterEntriesFat32 and filterEntriesNtfs (ExFAT is exempt because
// its code performs ReplaceAll backslash->/ before invalidity check).
func TestH1AllThreeExtractorsShareDefect(t *testing.T) {
	name := `..\evil`

	// Ext: tested above (passes).
	// FAT32: filterEntriesFat32 takes []os.FileInfo; reuse the same logic
	// by constructing a minimal os.FileInfo.
	fat32Info := fakeFileInfo{n: name}
	survivors := filterEntriesFat32([]os.FileInfo{fat32Info})
	if len(survivors) != 1 {
		t.Errorf("filterEntriesFat32 should accept %q (no /-byte) — got %d survivors", name, len(survivors))
	} else {
		t.Logf("CONFIRMED FAT32: filterEntriesFat32 accepts %q", name)
	}

	// NTFS uses *parser.FileInfo from www.velocidex.com/golang/go-ntfs/parser.
	// The filter logic is identical, so we only document by reference here.
	t.Logf("filterEntriesNtfs is structurally identical to filterEntriesExt/Fat32 " +
		"(common.go:122-133) and exhibits the same defect.")
	t.Logf("ExtractAllRecursiveExFAT (common.go:336-378) is NOT affected because " +
		"strings.ReplaceAll(relPath, `\\\\`, string(os.PathSeparator)) at common.go:338 " +
		"normalises backslash to / on Linux, triggering the contains-/ filter.")
}

type fakeFileInfo struct{ n string }

func (f fakeFileInfo) Name() string       { return f.n }
func (f fakeFileInfo) Size() int64        { return 0 }
func (f fakeFileInfo) Mode() os.FileMode  { return 0 }
func (f fakeFileInfo) ModTime() time.Time { return time.Time{} }
func (f fakeFileInfo) IsDir() bool        { return false }
func (f fakeFileInfo) Sys() any           { return nil }

func namesOf(entries []fs.DirEntry) []string {
	out := make([]string, len(entries))
	for i, e := range entries {
		out[i] = e.Name()
	}
	return out
}

func tsSuffix() string {
	return time.Now().UTC().Format("20060102T150405")
}

// windowsLikeJoin manually simulates the result of filepath.Join under
// GOOS=windows for use in skip messages on non-Windows runners. This is
// not a security primitive, only documentation aid.
func windowsLikeJoin(base, name string) string {
	joined := base + `\` + name
	joined = strings.ReplaceAll(joined, "/", `\`)
	parts := strings.Split(joined, `\`)
	var stack []string
	for _, p := range parts {
		switch p {
		case "", ".":
			// drop
		case "..":
			if len(stack) > 1 { // keep drive root
				stack = stack[:len(stack)-1]
			}
		default:
			stack = append(stack, p)
		}
	}
	return strings.Join(stack, `\`)
}
