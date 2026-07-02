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

//go:build linux

package ldsopreload

import (
	"context"
	"errors"
	"io"
	"io/fs"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/google/osv-scalibr/inventory"
	"github.com/google/osv-scalibr/packageindex"

	cpb "github.com/google/osv-scalibr/binary/proto/config_go_proto"
)

func extractIssues(finding inventory.Finding) []string {
	if len(finding.GenericFindings) == 0 {
		return nil
	}
	target := finding.GenericFindings[0].Target
	if target == nil || target.Extra == "" {
		return nil
	}
	return strings.Split(target.Extra, "\n")
}

type fakeFileInfo struct {
	name  string
	mode  fs.FileMode
	sys   any
	isDir bool
}

func (f fakeFileInfo) Name() string       { return f.name }
func (f fakeFileInfo) Size() int64        { return 0 }
func (f fakeFileInfo) Mode() fs.FileMode  { return f.mode }
func (f fakeFileInfo) ModTime() time.Time { return time.Time{} }
func (f fakeFileInfo) IsDir() bool        { return f.isDir }
func (f fakeFileInfo) Sys() any           { return f.sys }

type fakeFile struct {
	info fs.FileInfo
}

func (f fakeFile) Stat() (fs.FileInfo, error) { return f.info, nil }
func (fakeFile) Read([]byte) (int, error)     { return 0, io.EOF }
func (fakeFile) Close() error                 { return nil }

type testFS struct {
	entries map[string]fs.FileInfo
}

func (t testFS) Open(name string) (fs.File, error) {
	info, ok := t.entries[name]
	if !ok {
		return nil, fs.ErrNotExist
	}
	return fakeFile{info: info}, nil
}

func (t testFS) Stat(name string) (fs.FileInfo, error) {
	info, ok := t.entries[name]
	if !ok {
		return nil, fs.ErrNotExist
	}
	return info, nil
}

func newFileInfo(name string, mode fs.FileMode, uid, gid uint32, isDir bool) fs.FileInfo {
	return fakeFileInfo{
		name:  name,
		mode:  mode,
		sys:   &syscall.Stat_t{Uid: uid, Gid: gid},
		isDir: isDir,
	}
}

func baseEntries() map[string]fs.FileInfo {
	return map[string]fs.FileInfo{
		".":   newFileInfo(".", fs.ModeDir|0755, 0, 0, true),
		"etc": newFileInfo("etc", fs.ModeDir|0755, 0, 0, true),
		"etc/ld.so.preload": newFileInfo(
			"ld.so.preload", 0644, 0, 0, false),
	}
}

func baseEntriesWithoutPreload() map[string]fs.FileInfo {
	entries := baseEntries()
	delete(entries, "etc/ld.so.preload")
	return entries
}

func TestScanFS_missing_file_returns_no_finding(t *testing.T) {
	fsys := testFS{entries: baseEntriesWithoutPreload()}

	d := &Detector{}
	finding, err := d.ScanFS(
		context.Background(), fsys, &packageindex.PackageIndex{})
	if err != nil {
		t.Fatalf("ScanFS() returned error: %v", err)
	}

	if len(finding.GenericFindings) != 0 {
		t.Errorf("expected no findings, got: %v", finding)
	}
}

func TestScanFS_missing_file_insecure_parent_returns_finding(t *testing.T) {
	entries := baseEntriesWithoutPreload()
	entries["etc"] = newFileInfo("etc", fs.ModeDir|0777, 0, 0, true)
	fsys := testFS{entries: entries}

	d := &Detector{}
	finding, err := d.ScanFS(
		context.Background(), fsys, &packageindex.PackageIndex{})
	if err != nil {
		t.Fatalf("ScanFS() returned error: %v", err)
	}

	issues := extractIssues(finding)
	wantIssues := []string{
		"parent directory /etc is world-writable (permissions: 777)" +
			" - an attacker can create or replace ld.so.preload" +
			" to hijack the dynamic linker",
		"parent directory /etc is group-writable (permissions: 777)" +
			" - group members can create or replace ld.so.preload" +
			" to hijack the dynamic linker",
	}
	if diff := cmp.Diff(wantIssues, issues); diff != "" {
		t.Errorf("issues mismatch (-want +got):\n%s", diff)
	}
}

func TestScanFS_secure_file_and_parents_returns_no_finding(t *testing.T) {
	fsys := testFS{entries: baseEntries()}

	d := &Detector{}
	finding, err := d.ScanFS(
		context.Background(), fsys, &packageindex.PackageIndex{})
	if err != nil {
		t.Fatalf("ScanFS() returned error: %v", err)
	}

	issues := extractIssues(finding)
	if len(issues) > 0 {
		t.Errorf("expected no issues for secure config, got: %v", issues)
	}
}

func TestScanFS_world_writable_file_returns_finding(t *testing.T) {
	entries := baseEntries()
	entries["etc/ld.so.preload"] = newFileInfo(
		"ld.so.preload", 0666, 0, 0, false)
	fsys := testFS{entries: entries}

	d := &Detector{}
	finding, err := d.ScanFS(
		context.Background(), fsys, &packageindex.PackageIndex{})
	if err != nil {
		t.Fatalf("ScanFS() returned error: %v", err)
	}

	issues := extractIssues(finding)
	wantIssues := []string{
		"/etc/ld.so.preload is world-writable (permissions: 666)" +
			" - any local user can inject a malicious shared library" +
			" that will be loaded into every dynamically linked process",
		"/etc/ld.so.preload is group-writable (permissions: 666)" +
			" - members of the owning group can inject a malicious" +
			" shared library for preload hijacking",
	}
	if diff := cmp.Diff(wantIssues, issues); diff != "" {
		t.Errorf("issues mismatch (-want +got):\n%s", diff)
	}
}

func TestScanFS_group_writable_file_returns_finding(t *testing.T) {
	entries := baseEntries()
	entries["etc/ld.so.preload"] = newFileInfo(
		"ld.so.preload", 0664, 0, 0, false)
	fsys := testFS{entries: entries}

	d := &Detector{}
	finding, err := d.ScanFS(
		context.Background(), fsys, &packageindex.PackageIndex{})
	if err != nil {
		t.Fatalf("ScanFS() returned error: %v", err)
	}

	issues := extractIssues(finding)
	wantIssues := []string{
		"/etc/ld.so.preload is group-writable (permissions: 664)" +
			" - members of the owning group can inject a malicious" +
			" shared library for preload hijacking",
	}
	if diff := cmp.Diff(wantIssues, issues); diff != "" {
		t.Errorf("issues mismatch (-want +got):\n%s", diff)
	}
}

func TestScanFS_secure_file_world_writable_parent_returns_finding(t *testing.T) {
	entries := baseEntries()
	entries["etc"] = newFileInfo("etc", fs.ModeDir|0777, 0, 0, true)
	fsys := testFS{entries: entries}

	d := &Detector{}
	finding, err := d.ScanFS(
		context.Background(), fsys, &packageindex.PackageIndex{})
	if err != nil {
		t.Fatalf("ScanFS() returned error: %v", err)
	}

	issues := extractIssues(finding)
	wantIssues := []string{
		"parent directory /etc is world-writable (permissions: 777)" +
			" - an attacker can create or replace ld.so.preload" +
			" to hijack the dynamic linker",
		"parent directory /etc is group-writable (permissions: 777)" +
			" - group members can create or replace ld.so.preload" +
			" to hijack the dynamic linker",
	}
	if diff := cmp.Diff(wantIssues, issues); diff != "" {
		t.Errorf("issues mismatch (-want +got):\n%s", diff)
	}
}

func TestScanFS_secure_file_group_writable_parent_returns_finding(t *testing.T) {
	entries := baseEntries()
	entries["etc"] = newFileInfo("etc", fs.ModeDir|0775, 0, 0, true)
	fsys := testFS{entries: entries}

	d := &Detector{}
	finding, err := d.ScanFS(
		context.Background(), fsys, &packageindex.PackageIndex{})
	if err != nil {
		t.Fatalf("ScanFS() returned error: %v", err)
	}

	issues := extractIssues(finding)
	wantIssues := []string{
		"parent directory /etc is group-writable (permissions: 775)" +
			" - group members can create or replace ld.so.preload" +
			" to hijack the dynamic linker",
	}
	if diff := cmp.Diff(wantIssues, issues); diff != "" {
		t.Errorf("issues mismatch (-want +got):\n%s", diff)
	}
}

func TestScanFS_file_not_owned_by_root_returns_finding(t *testing.T) {
	entries := baseEntries()
	entries["etc/ld.so.preload"] = newFileInfo(
		"ld.so.preload", 0644, 1000, 1000, false)
	fsys := testFS{entries: entries}

	d := &Detector{}
	finding, err := d.ScanFS(
		context.Background(), fsys, &packageindex.PackageIndex{})
	if err != nil {
		t.Fatalf("ScanFS() returned error: %v", err)
	}

	issues := extractIssues(finding)
	wantIssues := []string{
		"/etc/ld.so.preload is not owned by root (uid: 1000)",
		"/etc/ld.so.preload is not group-owned by root (gid: 1000)",
	}
	if diff := cmp.Diff(wantIssues, issues); diff != "" {
		t.Errorf("issues mismatch (-want +got):\n%s", diff)
	}
}

func TestScanFS_parent_dir_not_owned_by_root_returns_finding(t *testing.T) {
	entries := baseEntries()
	entries["etc"] = newFileInfo("etc", fs.ModeDir|0755, 1000, 1000, true)
	fsys := testFS{entries: entries}

	d := &Detector{}
	finding, err := d.ScanFS(
		context.Background(), fsys, &packageindex.PackageIndex{})
	if err != nil {
		t.Fatalf("ScanFS() returned error: %v", err)
	}

	issues := extractIssues(finding)
	wantIssues := []string{
		"parent directory /etc is not owned by root (uid: 1000)",
		"parent directory /etc is not group-owned by root (gid: 1000)",
	}
	if diff := cmp.Diff(wantIssues, issues); diff != "" {
		t.Errorf("issues mismatch (-want +got):\n%s", diff)
	}
}

func TestScanFS_multiple_issues_aggregated(t *testing.T) {
	entries := baseEntries()
	entries["etc"] = newFileInfo("etc", fs.ModeDir|0777, 0, 0, true)
	entries["etc/ld.so.preload"] = newFileInfo(
		"ld.so.preload", 0666, 0, 0, false)
	fsys := testFS{entries: entries}

	d := &Detector{}
	finding, err := d.ScanFS(
		context.Background(), fsys, &packageindex.PackageIndex{})
	if err != nil {
		t.Fatalf("ScanFS() returned error: %v", err)
	}

	issues := extractIssues(finding)
	// Expect 4 issues: file world-writable + file group-writable +
	// parent world-writable + parent group-writable.
	if len(issues) != 4 {
		t.Errorf("expected 4 issues, got %d: %v", len(issues), issues)
	}

	foundFileWorld := false
	foundFileGroup := false
	foundDirWorld := false
	foundDirGroup := false
	for _, issue := range issues {
		switch {
		case strings.Contains(issue, "ld.so.preload is world-writable"):
			foundFileWorld = true
		case strings.Contains(issue, "ld.so.preload is group-writable"):
			foundFileGroup = true
		case strings.Contains(issue, "/etc is world-writable"):
			foundDirWorld = true
		case strings.Contains(issue, "/etc is group-writable"):
			foundDirGroup = true
		}
	}

	if !foundFileWorld {
		t.Error("expected file world-writable issue")
	}
	if !foundFileGroup {
		t.Error("expected file group-writable issue")
	}
	if !foundDirWorld {
		t.Error("expected parent dir world-writable issue")
	}
	if !foundDirGroup {
		t.Error("expected parent dir group-writable issue")
	}
}

func TestScanFS_context_canceled_returns_error(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	fsys := testFS{entries: baseEntries()}

	d := &Detector{}
	_, err := d.ScanFS(ctx, fsys, &packageindex.PackageIndex{})
	if err == nil {
		t.Error("expected error for canceled context, got nil")
	}
}

func TestDetectorInterface(t *testing.T) {
	d, err := New(&cpb.PluginConfig{})
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	if d.Name() != Name {
		t.Errorf("Name() = %q, want %q", d.Name(), Name)
	}

	if d.Version() != 0 {
		t.Errorf("Version() = %d, want 0", d.Version())
	}

	if len(d.RequiredExtractors()) != 0 {
		t.Errorf("RequiredExtractors() should be empty")
	}

	finding := d.DetectedFinding()
	if len(finding.GenericFindings) != 1 {
		t.Fatalf("DetectedFinding() expected 1 finding, got %d",
			len(finding.GenericFindings))
	}

	gf := finding.GenericFindings[0]
	if gf.Adv.Sev != inventory.SeverityHigh {
		t.Errorf("severity = %v, want High", gf.Adv.Sev)
	}
	if gf.Adv.ID.Publisher != "SCALIBR" {
		t.Errorf("publisher = %q, want SCALIBR", gf.Adv.ID.Publisher)
	}
	if gf.Adv.ID.Reference != "ld-so-preload-hijack" {
		t.Errorf("reference = %q, want ld-so-preload-hijack",
			gf.Adv.ID.Reference)
	}
	if gf.Target != nil {
		t.Errorf("DetectedFinding() target should be nil")
	}
}

func TestScanFS_only_other_write_on_file(t *testing.T) {
	entries := baseEntries()
	entries["etc/ld.so.preload"] = newFileInfo(
		"ld.so.preload", 0646, 0, 0, false)
	fsys := testFS{entries: entries}

	d := &Detector{}
	finding, err := d.ScanFS(
		context.Background(), fsys, &packageindex.PackageIndex{})
	if err != nil {
		t.Fatalf("ScanFS() returned error: %v", err)
	}

	issues := extractIssues(finding)
	wantIssues := []string{
		"/etc/ld.so.preload is world-writable (permissions: 646)" +
			" - any local user can inject a malicious shared library" +
			" that will be loaded into every dynamically linked process",
	}
	if diff := cmp.Diff(wantIssues, issues); diff != "" {
		t.Errorf("issues mismatch (-want +got):\n%s", diff)
	}
}

func TestScanFS_empty_preload_file_still_checked(t *testing.T) {
	entries := baseEntries()
	entries["etc/ld.so.preload"] = newFileInfo(
		"ld.so.preload", 0666, 0, 0, false)
	fsys := testFS{entries: entries}

	d := &Detector{}
	finding, err := d.ScanFS(
		context.Background(), fsys, &packageindex.PackageIndex{})
	if err != nil {
		t.Fatalf("ScanFS() returned error: %v", err)
	}

	issues := extractIssues(finding)
	if len(issues) == 0 {
		t.Error("expected issues for world-writable empty preload file")
	}
}

type openErrorFS struct {
	openErr error
}

func (fsys openErrorFS) Open(name string) (fs.File, error) {
	return nil, fsys.openErr
}

type statErrorFile struct {
	statErr error
}

func (file statErrorFile) Stat() (fs.FileInfo, error) { return nil, file.statErr }
func (statErrorFile) Read([]byte) (int, error)        { return 0, io.EOF }
func (statErrorFile) Close() error                    { return nil }

type statErrorFS struct {
	statErr error
}

func (fsys statErrorFS) Open(name string) (fs.File, error) {
	return statErrorFile(fsys), nil
}

func (fsys statErrorFS) Stat(name string) (fs.FileInfo, error) {
	return nil, fsys.statErr
}

func TestScanFS_open_error_returns_error(t *testing.T) {
	fsys := openErrorFS{openErr: fs.ErrPermission}

	d := &Detector{}
	_, err := d.ScanFS(context.Background(), fsys, &packageindex.PackageIndex{})
	if err == nil {
		t.Fatal("expected error for open failure, got nil")
	}
	if !errors.Is(err, fs.ErrPermission) {
		t.Fatalf("expected permission error, got: %v", err)
	}
}

func TestScanFS_stat_error_returns_error(t *testing.T) {
	errStat := errors.New("stat failed")
	fsys := statErrorFS{statErr: errStat}

	d := &Detector{}
	_, err := d.ScanFS(context.Background(), fsys, &packageindex.PackageIndex{})
	if err == nil {
		t.Fatal("expected error for stat failure, got nil")
	}
	if !errors.Is(err, errStat) {
		t.Fatalf("expected stat error, got: %v", err)
	}
}

func TestScanFS_non_directory_parent_returns_error(t *testing.T) {
	entries := baseEntries()
	entries["etc"] = newFileInfo("etc", 0644, 0, 0, false)
	fsys := testFS{entries: entries}

	d := &Detector{}
	_, err := d.ScanFS(context.Background(), fsys, &packageindex.PackageIndex{})
	if err == nil {
		t.Fatal("expected error for non-directory /etc, got nil")
	}
	if !errors.Is(err, errNotDir) {
		t.Fatalf("expected directory error, got: %v", err)
	}
}
