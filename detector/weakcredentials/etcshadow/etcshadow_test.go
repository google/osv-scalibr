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

package etcshadow_test

import (
	"context"
	"errors"
	"io"
	"io/fs"
	"os"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/google/osv-scalibr/detector"
	"github.com/google/osv-scalibr/detector/weakcredentials/etcshadow"
	"github.com/google/osv-scalibr/extractor"
	scalibrfs "github.com/google/osv-scalibr/fs"
	"github.com/google/osv-scalibr/inventoryindex"
)

// All users have the password "Password123" using distinct hashing algorithms.
var sampleEtcShadow = "" +
	"user-yescrypt:$y$j9T$huXYrFRxr5.EtlA/GqJQg1$R36Nu5MbY5YM0SzRaWbBPyGpM7KMcWtbUmBq5gDZA9B\n" +
	"user-gost-yescrypt:$gy$j9T$i.krMgTvuXE2doi6Hguka/$qwn482j7gJbWZNQ3cF0YdKAud.C3vUIorQGsF0ryox3\n" +
	"user-scrypt:$7$CU..../....oupVTCfqrgm0HQkQR3JaB1$2m9CeDTqL8i5pMsc8E73A2bCIsvQPhntxBmSVlbrql2\n" +
	"user-bcrypt:$2b$05$IYDlXvHmeORyyiUwu8KKuek2LE8VrxIYZ2skPvRDDNngpXJHRq7sG\n" +
	"user-bcrypt-a:$2a$05$pRmHHyGfKl9/9AZLORG/neKW39VHGF4ptLT2MLq1BqQOnbwL6DQM6:3rdfield\n" +
	"user-bcrypt-a\n" + // entry skipped, no ':' separator
	"user-sha512crypt:$6$5dZ5RtTlA.rNzi8o$sE23IbqB0Q57/7nI2.AqazHUnWGP06HmkadfBJ90mHgAHkWVZteoaUWV25jITMIUXC/buIgZ9hU2JYQM5qGZn1\n" +
	"user-sha256crypt:$5$bMDt75aAcRJMgynJ$7dvcQe0UPWAlpr4VFNQI2iDDUQLgwcaTOV5oQVSIR56\n" +
	"user-sunmd5:$md5,rounds=46947$ieGPlcPv$$sJ4xQqZ5DHZu0Bma2EW/..\n" +
	"user-md5crypt:$1$emQTNiRX$kZ2UzRTLgfsTBGS0M1OOb1\n" +
	"user-NT-Hash:$3$$58a478135a93ac3bf058a5ea0e8fdb71\n" +
	"user-bsdicrypt:_J9..Sc51o5Op8yDIuHc\n" +
	"user-descrypt:chERDiI95PGCQ\n" +
	"user-descrypt2:chERDiI95PGCQ:abc\n" + // entry with more than 2 fields
	""

// Minimal fake fs.FS implementation that supports reading from files a set content.
// Used to fake read from /etc/shadow a given set of password hashes.
type fakeFS struct {
	files map[string]string
}

func (f fakeFS) Open(name string) (fs.File, error) {
	if content, ok := f.files[name]; ok {
		return &fakeFile{content, 0}, nil
	}
	return nil, os.ErrNotExist
}
func (fakeFS) ReadDir(name string) ([]fs.DirEntry, error) {
	return nil, errors.New("not implemented")
}
func (fakeFS) Stat(name string) (fs.FileInfo, error) {
	return nil, errors.New("not implemented")
}

type fakeFile struct {
	content  string
	position int
}

func (f *fakeFile) Stat() (fs.FileInfo, error) {
	return nil, nil
}

func (f *fakeFile) Read(buffer []byte) (count int, err error) {
	size := copy(buffer, f.content[f.position:])
	if size > 0 {
		f.position += size
		return size, nil
	}
	return 0, io.EOF
}

func (*fakeFile) Close() error {
	return nil
}

func TestScan(t *testing.T) {
	wantTitle := "Ensure all users have strong passwords configured"
	wantDesc := "The /etc/shadow file contains user account password hashes. " +
		"These passwords must be strong and not easily guessable."
	wantRec := "Run the following command to reset password for the reported users:\n" +
		"# change password for USER: sudo passwd USER"
	wantAdv := &detector.Advisory{
		ID: &detector.AdvisoryID{
			Publisher: "SCALIBR",
			Reference: "etc-shadow-weakcredentials",
		},
		Type:           detector.TypeVulnerability,
		Title:          wantTitle,
		Description:    wantDesc,
		Recommendation: wantRec,
		Sev:            &detector.Severity{Severity: detector.SeverityCritical},
	}

	ix, _ := inventoryindex.New([]*extractor.Inventory{})
	testCases := []struct {
		desc         string
		fsys         scalibrfs.FS
		wantFindings []*detector.Finding
		wantErr      error
	}{
		{
			desc: "File doesn't exist",
			fsys: &fakeFS{},
		},
		{
			desc: "File empty",
			fsys: &fakeFS{files: map[string]string{"etc/shadow": ""}},
		},
		{
			desc: "File with incorrect format",
			fsys: &fakeFS{files: map[string]string{"etc/shadow": "x\ny\n"}},
		},
		{
			desc: "File without hashes",
			fsys: &fakeFS{files: map[string]string{"etc/shadow": "x:!:stuff\ny:*:stuff\nz:!!:stuff\n"}},
		},
		{
			desc: "File with hashes, some cracked",
			fsys: &fakeFS{files: map[string]string{"etc/shadow": sampleEtcShadow}},
			wantFindings: []*detector.Finding{{
				Adv:    wantAdv,
				Target: &detector.TargetDetails{Location: []string{"/etc/shadow"}},
				Extra: "The following users have weak passwords:\n" +
					"user-bcrypt\n" + "user-bcrypt-a\n" + "user-sha512crypt\n",
			}},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.desc, func(t *testing.T) {
			detector := etcshadow.Detector{}
			findings, err := detector.Scan(t.Context(), &scalibrfs.ScanRoot{FS: tc.fsys}, ix)
			if diff := cmp.Diff(tc.wantErr, err, cmpopts.EquateErrors()); diff != "" {
				t.Fatalf("detector.Scan(%v): unexpected error (-want +got):\n%s", tc.fsys, diff)
			}
			if err == nil {
				if diff := cmp.Diff(tc.wantFindings, findings); diff != "" {
					t.Errorf("detector.Scan(%v): unexpected findings (-want +got):\n%s", tc.fsys, diff)
				}
			}
		})
	}
}

func TestScanCancelled(t *testing.T) {
	ix, _ := inventoryindex.New([]*extractor.Inventory{})
	detector := etcshadow.Detector{}
	fsys := &fakeFS{files: map[string]string{"etc/shadow": sampleEtcShadow}}
	ctx, cancelFunc := context.WithCancel(t.Context())
	cancelFunc()
	findings, err := detector.Scan(ctx, &scalibrfs.ScanRoot{FS: fsys}, ix)
	if findings != nil || err != ctx.Err() {
		t.Errorf("expected scan to be cancelled")
	}
}
