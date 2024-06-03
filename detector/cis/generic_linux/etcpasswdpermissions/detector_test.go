// Copyright 2024 Google LLC
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

package etcpasswdpermissions_test

import (
	"context"
	"errors"
	"io/fs"
	"os"
	"syscall"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/google/osv-scalibr/detector/cis/generic_linux/etcpasswdpermissions"
	"github.com/google/osv-scalibr/detector"
	"github.com/google/osv-scalibr/extractor"
	"github.com/google/osv-scalibr/inventoryindex"
)

// A fake implementation of fs.FS where the only file is /etc/passwd and it has configurable permissions.
type fakeFS struct {
	exists bool
	perms  fs.FileMode
	uid    uint32
	gid    uint32
}

func (f *fakeFS) Open(name string) (fs.File, error) {
	if name == "etc/passwd" {
		if f.exists {
			return &fakeFile{perms: f.perms, uid: f.uid, gid: f.gid}, nil
		}
		return nil, os.ErrNotExist
	}
	return nil, errors.New("failed to open")
}

type fakeFile struct {
	perms fs.FileMode
	uid   uint32
	gid   uint32
}

func (f *fakeFile) Stat() (fs.FileInfo, error) {
	return &fakeFileInfo{perms: f.perms, uid: f.uid, gid: f.gid}, nil
}
func (fakeFile) Read([]byte) (int, error) { return 0, errors.New("failed to read") }
func (fakeFile) Close() error             { return nil }

type fakeFileInfo struct {
	perms fs.FileMode
	uid   uint32
	gid   uint32
}

func (fakeFileInfo) Name() string         { return "/etc/passwd" }
func (fakeFileInfo) Size() int64          { return 1 }
func (i *fakeFileInfo) Mode() fs.FileMode { return i.perms }
func (fakeFileInfo) ModTime() time.Time   { return time.Now() }
func (i *fakeFileInfo) IsDir() bool       { return false }
func (i *fakeFileInfo) Sys() any          { return &syscall.Stat_t{Uid: i.uid, Gid: i.gid} }

func TestScan(t *testing.T) {
	wantTitle := "Ensure permissions on /etc/passwd are configured"
	wantDesc := "The /etc/passwd file contains user account information that " +
		"is used by many system utilities and therefore must be readable for these " +
		"utilities to operate."
	wantRec := "Run the following command to set permissions on /etc/passwd :\n" +
		"# chown root:root /etc/passwd\n" +
		"# chmod 644 /etc/passwd"
	wantAdv := &detector.Advisory{
		ID: &detector.AdvisoryID{
			Publisher: "CIS",
			Reference: "etc-passwd-permissions",
		},
		Type:           detector.TypeCISFinding,
		Title:          wantTitle,
		Description:    wantDesc,
		Recommendation: wantRec,
		Sev:            &detector.Severity{Severity: detector.SeverityMinimal},
	}

	ix, _ := inventoryindex.New([]*extractor.Inventory{})
	testCases := []struct {
		desc         string
		fsys         fs.FS
		wantFindings []*detector.Finding
		wantErr      error
	}{
		{
			desc:         "File doesn't exist",
			fsys:         &fakeFS{exists: false},
			wantFindings: nil,
		},
		{
			desc:         "Permissions correct",
			fsys:         &fakeFS{exists: true, perms: 0644, uid: 0, gid: 0},
			wantFindings: nil,
		},
		{
			desc: "Permissions incorrect",
			fsys: &fakeFS{exists: true, perms: 0777, uid: 0, gid: 0},
			wantFindings: []*detector.Finding{&detector.Finding{
				Adv:    wantAdv,
				Target: &detector.TargetDetails{Location: []string{"/etc/passwd"}},
				Extra:  "file permissions 777, expected 644\n",
			}},
		},
		{
			desc: "Permissions and uid incorrect",
			fsys: &fakeFS{exists: true, perms: 0777, uid: 10, gid: 0},
			wantFindings: []*detector.Finding{&detector.Finding{
				Adv:    wantAdv,
				Target: &detector.TargetDetails{Location: []string{"/etc/passwd"}},
				Extra:  "file permissions 777, expected 644\nfile owner 10, expected 0/root\n",
			}},
		},
		{
			desc: "Permissions and gid incorrect",
			fsys: &fakeFS{exists: true, perms: 0777, uid: 0, gid: 10},
			wantFindings: []*detector.Finding{&detector.Finding{
				Adv:    wantAdv,
				Target: &detector.TargetDetails{Location: []string{"/etc/passwd"}},
				Extra:  "file permissions 777, expected 644\nfile group 10, expected 0/root\n",
			}},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.desc, func(t *testing.T) {
			det := etcpasswdpermissions.Detector{}
			findings, err := det.ScanFS(context.Background(), tc.fsys, ix)
			if diff := cmp.Diff(tc.wantErr, err, cmpopts.EquateErrors()); diff != "" {
				t.Errorf("detector.Scan(%v): unexpected error (-want +got):\n%s", tc.fsys, diff)
			}
			if diff := cmp.Diff(tc.wantFindings, findings); diff != "" {
				t.Errorf("detector.Scan(%v): unexpected findings (-want +got):\n%s", tc.fsys, diff)
			}
		})
	}
}
