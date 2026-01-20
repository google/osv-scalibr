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

//go:build !windows

package cronjobprivesc

import (
	"context"
	"fmt"
	"io/fs"
	"strings"
	"syscall"
	"testing"
	"testing/fstest"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/google/osv-scalibr/packageindex"
)

func expectWorldWritableFile(file string, line int, path string) string {
	return fmt.Sprintf("%s:%d: '%s' is world-writable (permissions: 777)", file, line, path)
}

func expectGroupWritableFile(file string, line int, path string, perms fs.FileMode) string {
	return fmt.Sprintf("%s:%d: '%s' is group-writable (permissions: %03o)", file, line, path, perms.Perm())
}

func expectNonRootOwner(file string, line int, path string, uid int) string {
	return fmt.Sprintf("%s:%d: '%s' is not owned by root (uid: %d)", file, line, path, uid)
}

func TestLinuxCronJobsFilePermissions(t *testing.T) {
	tests := []struct {
		name       string
		scriptPath string
		perms      fs.FileMode
		uid        uint32
		gid        uint32
		cronEntry  string
		wantIssues []string
	}{
		{
			name:       "secure script permissions",
			scriptPath: "usr/bin/backup.sh",
			perms:      0755, // rwxr-xr-x
			uid:        0,    // root
			gid:        0,    // root
			cronEntry:  "0 0 * * * root /usr/bin/backup.sh",
			wantIssues: nil,
		},
		{
			name:       "world-writable script",
			scriptPath: "usr/bin/bad_script.sh",
			perms:      0777, // rwxrwxrwx
			uid:        0,
			gid:        0,
			cronEntry:  "0 0 * * * root /usr/bin/bad_script.sh",
			wantIssues: []string{
				expectWorldWritableFile("etc/crontab", 1, "/usr/bin/bad_script.sh"),
				expectGroupWritableFile("etc/crontab", 1, "/usr/bin/bad_script.sh", 0777),
			},
		},
		{
			name:       "group-writable script",
			scriptPath: "usr/bin/group_writable.sh",
			perms:      0775, // rwxrwxr-x
			uid:        0,
			gid:        0,
			cronEntry:  "0 0 * * * root /usr/bin/group_writable.sh",
			wantIssues: []string{expectGroupWritableFile("etc/crontab", 1, "/usr/bin/group_writable.sh", 0775)},
		},
		{
			name:       "non-root owned script",
			scriptPath: "usr/bin/user_owned.sh",
			perms:      0755,
			uid:        1000, // non-root user
			gid:        0,
			cronEntry:  "0 0 * * * root /usr/bin/user_owned.sh",
			wantIssues: []string{expectNonRootOwner("etc/crontab", 1, "/usr/bin/user_owned.sh", 1000)},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			stat := &syscall.Stat_t{
				Uid: tt.uid,
				Gid: tt.gid,
			}

			fsys := &testFS{
				MapFS: fstest.MapFS{
					"etc/crontab": &fstest.MapFile{Data: []byte(tt.cronEntry)},
				},
				customFiles: map[string]fakeFile{
					tt.scriptPath: {
						MapFile: &fstest.MapFile{Data: []byte("#!/bin/bash\necho 'test'\n")},
						info: fakeFileInfo{
							name:    "script.sh",
							mode:    tt.perms,
							modTime: time.Now(),
							sys:     stat,
						},
					},
				},
			}

			d := &Detector{}
			finding, err := d.ScanFS(context.Background(), fsys, &packageindex.PackageIndex{})

			if err != nil {
				t.Errorf("ScanFS() returned error: %v", err)
			}

			actualIssues := extractIssues(finding)

			if diff := cmp.Diff(tt.wantIssues, actualIssues); diff != "" {
				t.Errorf("File permissions test mismatch (-want +got):\n%s", diff)
			}
		})
	}
}

func TestCronPeriodicDirectories(t *testing.T) {
	tests := []struct {
		name         string
		setupFS      func() *testFS
		wantIssues   []string
		wantNoIssues bool
	}{
		{
			name: "secure script in cron.daily",
			setupFS: func() *testFS {
				return &testFS{
					MapFS: fstest.MapFS{},
					customFiles: map[string]fakeFile{
						"etc/cron.daily/backup": {
							MapFile: &fstest.MapFile{Data: []byte("#!/bin/bash\necho 'backup'\n")},
							info: fakeFileInfo{
								name:    "backup",
								mode:    0755, // rwxr-xr-x
								modTime: time.Now(),
								sys:     &syscall.Stat_t{Uid: 0, Gid: 0},
							},
						},
					},
				}
			},
			wantNoIssues: true,
		},
		{
			name: "world-writable script in cron.hourly",
			setupFS: func() *testFS {
				return &testFS{
					MapFS: fstest.MapFS{},
					customFiles: map[string]fakeFile{
						"etc/cron.hourly/malicious": {
							MapFile: &fstest.MapFile{Data: []byte("#!/bin/bash\necho 'malicious'\n")},
							info: fakeFileInfo{
								name:    "malicious",
								mode:    0777, // rwxrwxrwx
								modTime: time.Now(),
								sys:     &syscall.Stat_t{Uid: 0, Gid: 0},
							},
						},
					},
				}
			},
			wantIssues: []string{"'etc/cron.hourly/malicious' is world-writable (permissions: 777)"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create filesystem once
			testFS := tt.setupFS()

			// Add the directory entry to the filesystem
			if testFS.customFiles != nil {
				for path := range testFS.customFiles {
					dir := strings.Split(path, "/")
					if len(dir) > 1 {
						dirPath := strings.Join(dir[:len(dir)-1], "/")
						testFS.MapFS[dirPath] = &fstest.MapFile{Mode: fs.ModeDir}
					}
				}
			}

			d := &Detector{}
			finding, err := d.ScanFS(context.Background(), testFS, &packageindex.PackageIndex{})

			if err != nil {
				t.Errorf("ScanFS() returned error: %v", err)
			}

			actualIssues := extractIssues(finding)

			if tt.wantNoIssues {
				if len(actualIssues) > 0 {
					t.Errorf("Expected no issues but got: %v", actualIssues)
				}
			} else {
				found := false
				for _, issue := range actualIssues {
					for _, wantIssue := range tt.wantIssues {
						if strings.Contains(issue, wantIssue) {
							found = true
							break
						}
					}
				}
				if !found {
					t.Errorf("Expected issues containing %v, but got: %v", tt.wantIssues, actualIssues)
				}
			}
		})
	}
}
