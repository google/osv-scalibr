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

package etcpasswdpermissions_test

import (
	"io/fs"
	"runtime"
	"slices"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/google/osv-scalibr/detector"
	"github.com/google/osv-scalibr/detector/cis/generic_linux/etcpasswdpermissions"
	"github.com/google/osv-scalibr/extractor"
	scalibrfs "github.com/google/osv-scalibr/fs"
	"github.com/google/osv-scalibr/inventoryindex"
)

// A fake implementation of fs.FS where the only file is /etc/passwd and it has configurable permissions.
type fakeFS struct {
	exists bool
	perms  fs.FileMode
	uid    uint32
	gid    uint32
}

type fakeFile struct {
	perms fs.FileMode
	uid   uint32
	gid   uint32
}

type fakeFileInfo struct {
	perms fs.FileMode
	uid   uint32
	gid   uint32
}

func TestScan(t *testing.T) {
	if !slices.Contains([]string{"linux"}, runtime.GOOS) {
		t.Skipf("Skipping test for unsupported OS %q", runtime.GOOS)
	}

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
		fsys         scalibrfs.FS
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
			wantFindings: []*detector.Finding{{
				Adv:    wantAdv,
				Target: &detector.TargetDetails{Location: []string{"/etc/passwd"}},
				Extra:  "file permissions 777, expected 644\n",
			}},
		},
		{
			desc: "Permissions and uid incorrect",
			fsys: &fakeFS{exists: true, perms: 0777, uid: 10, gid: 0},
			wantFindings: []*detector.Finding{{
				Adv:    wantAdv,
				Target: &detector.TargetDetails{Location: []string{"/etc/passwd"}},
				Extra:  "file permissions 777, expected 644\nfile owner 10, expected 0/root\n",
			}},
		},
		{
			desc: "Permissions and gid incorrect",
			fsys: &fakeFS{exists: true, perms: 0777, uid: 0, gid: 10},
			wantFindings: []*detector.Finding{{
				Adv:    wantAdv,
				Target: &detector.TargetDetails{Location: []string{"/etc/passwd"}},
				Extra:  "file permissions 777, expected 644\nfile group 10, expected 0/root\n",
			}},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.desc, func(t *testing.T) {
			det := etcpasswdpermissions.Detector{}
			findings, err := det.Scan(t.Context(), &scalibrfs.ScanRoot{FS: tc.fsys}, ix)
			if diff := cmp.Diff(tc.wantErr, err, cmpopts.EquateErrors()); diff != "" {
				t.Errorf("detector.Scan(%v): unexpected error (-want +got):\n%s", tc.fsys, diff)
			}
			if diff := cmp.Diff(tc.wantFindings, findings); diff != "" {
				t.Errorf("detector.Scan(%v): unexpected findings (-want +got):\n%s", tc.fsys, diff)
			}
		})
	}
}
