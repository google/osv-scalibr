//go:build linux

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

package dockersocket

import (
	"context"
	"io"
	"io/fs"
	"syscall"
	"testing"
	"testing/fstest"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/google/osv-scalibr/inventory"
	"github.com/google/osv-scalibr/packageindex"
	"github.com/google/osv-scalibr/plugin"
)

// fakeFileInfo implements fs.FileInfo for testing
type fakeFileInfo struct {
	name    string
	size    int64
	mode    fs.FileMode
	modTime time.Time
	isDir   bool
	sys     interface{}
}

func (f fakeFileInfo) Name() string       { return f.name }
func (f fakeFileInfo) Size() int64        { return f.size }
func (f fakeFileInfo) Mode() fs.FileMode  { return f.mode }
func (f fakeFileInfo) ModTime() time.Time { return f.modTime }
func (f fakeFileInfo) IsDir() bool        { return f.isDir }
func (f fakeFileInfo) Sys() interface{}   { return f.sys }

// fakeFile implements fs.File for testing
type fakeFile struct {
	*fstest.MapFile
	info   fakeFileInfo
	offset int
}

func (f fakeFile) Stat() (fs.FileInfo, error) {
	return f.info, nil
}

func (f fakeFile) Close() error {
	return nil
}

func (f *fakeFile) Read(b []byte) (int, error) {
	if f.offset >= len(f.MapFile.Data) {
		return 0, io.EOF
	}
	n := copy(b, f.MapFile.Data[f.offset:])
	f.offset += n
	return n, nil
}

func TestDockerSocketPermissions(t *testing.T) {
	tests := []struct {
		name        string
		socketPerms fs.FileMode
		uid         uint32
		gid         uint32
		wantIssues  int
	}{
		{
			name:        "secure socket permissions",
			socketPerms: 0660, // rw-rw----
			uid:         0,    // root
			gid:         999,  // docker group
			wantIssues:  0,
		},
		{
			name:        "world-readable socket",
			socketPerms: 0664, // rw-rw-r--
			uid:         0,
			gid:         999,
			wantIssues:  1,
		},
		{
			name:        "world-writable socket",
			socketPerms: 0666, // rw-rw-rw-
			uid:         0,
			gid:         999,
			wantIssues:  2, // both readable and writable
		},
		{
			name:        "non-root owner",
			socketPerms: 0660,
			uid:         1000, // non-root
			gid:         999,
			wantIssues:  1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			stat := &syscall.Stat_t{
				Uid: tt.uid,
				Gid: tt.gid,
			}

			fsys := fstest.MapFS{
				"var/run/docker.sock": &fstest.MapFile{
					Data: []byte{}, // Empty content, we're testing permissions
				},
			}

			// Override the file with our custom info
			file := fakeFile{
				MapFile: fsys["var/run/docker.sock"],
				info: fakeFileInfo{
					name:    "docker.sock",
					mode:    tt.socketPerms,
					modTime: time.Now(),
					sys:     stat,
				},
			}

			// Create a custom filesystem that returns our fake file
			customFS := &testFS{
				MapFS:    fsys,
				sockFile: file,
			}

			d := &Detector{}
			issues := d.checkDockerSocketPermissions(customFS)

			if len(issues) != tt.wantIssues {
				t.Errorf("checkDockerSocketPermissions() got %d issues, want %d: %v", len(issues), tt.wantIssues, issues)
			}
		})
	}
}

// testFS wraps fstest.MapFS to return our custom file for docker.sock
type testFS struct {
	fstest.MapFS
	sockFile fakeFile
}

func (t *testFS) Open(name string) (fs.File, error) {
	if name == "var/run/docker.sock" {
		return &t.sockFile, nil
	}
	return t.MapFS.Open(name)
}

func TestDockerDaemonConfig(t *testing.T) {
	tests := []struct {
		name       string
		config     string
		wantIssues int
	}{
		{
			name:       "secure config - no hosts",
			config:     `{}`,
			wantIssues: 0,
		},
		{
			name:       "secure config - unix socket only",
			config:     `{"hosts": ["unix:///var/run/docker.sock"]}`,
			wantIssues: 0,
		},
		{
			name:       "insecure config - tcp without tls",
			config:     `{"hosts": ["tcp://0.0.0.0:2375"]}`,
			wantIssues: 1,
		},
		{
			name:       "mixed config - both secure and insecure",
			config:     `{"hosts": ["unix:///var/run/docker.sock", "tcp://0.0.0.0:2375"]}`,
			wantIssues: 1,
		},
		{
			name:       "multiple insecure hosts",
			config:     `{"hosts": ["tcp://0.0.0.0:2375", "tcp://127.0.0.1:2376"]}`,
			wantIssues: 2,
		},
		{
			name:       "invalid json",
			config:     `{invalid json}`,
			wantIssues: 0, // Should not error on invalid JSON
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fsys := fstest.MapFS{
				"etc/docker/daemon.json": &fstest.MapFile{
					Data: []byte(tt.config),
				},
			}

			d := &Detector{}
			issues := d.checkDockerDaemonConfig(fsys)

			if len(issues) != tt.wantIssues {
				t.Errorf("checkDockerDaemonConfig() got %d issues, want %d: %v", len(issues), tt.wantIssues, issues)
			}
		})
	}
}

func TestSystemdServiceConfig(t *testing.T) {
	tests := []struct {
		name        string
		serviceFile string
		wantIssues  int
	}{
		{
			name: "secure service - unix socket only",
			serviceFile: `[Unit]
Description=Docker Application Container Engine

[Service]
ExecStart=/usr/bin/dockerd -H unix:///var/run/docker.sock

[Install]
WantedBy=multi-user.target`,
			wantIssues: 0,
		},
		{
			name: "insecure service - tcp without tls",
			serviceFile: `[Unit]
Description=Docker Application Container Engine

[Service]
ExecStart=/usr/bin/dockerd -H tcp://0.0.0.0:2375

[Install]
WantedBy=multi-user.target`,
			wantIssues: 1,
		},
		{
			name: "secure service - tcp with tls",
			serviceFile: `[Unit]
Description=Docker Application Container Engine

[Service]
ExecStart=/usr/bin/dockerd -H tcp://0.0.0.0:2376 --tls --tlscert=/path/to/cert.pem --tlskey=/path/to/key.pem

[Install]
WantedBy=multi-user.target`,
			wantIssues: 0,
		},
		{
			name: "multiple ExecStart lines - some insecure",
			serviceFile: `[Unit]
Description=Docker Application Container Engine

[Service]
ExecStart=/usr/bin/dockerd -H unix:///var/run/docker.sock
ExecStart=/usr/bin/dockerd -H tcp://0.0.0.0:2375

[Install]
WantedBy=multi-user.target`,
			wantIssues: 1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fsys := fstest.MapFS{
				"etc/systemd/system/docker.service": &fstest.MapFile{
					Data: []byte(tt.serviceFile),
				},
			}

			d := &Detector{}
			issues := d.checkSystemdServiceConfig(fsys)

			if len(issues) != tt.wantIssues {
				t.Errorf("checkSystemdServiceConfig() got %d issues, want %d: %v", len(issues), tt.wantIssues, issues)
			}
		})
	}
}

func TestScanFS_NoDocker(t *testing.T) {
	// Test with no Docker installation (no socket, no config files)
	fsys := fstest.MapFS{}

	d := &Detector{}
	finding, err := d.ScanFS(context.Background(), fsys, &packageindex.PackageIndex{})

	if err != nil {
		t.Errorf("ScanFS() returned error: %v", err)
	}

	if len(finding.GenericFindings) != 0 {
		t.Errorf("ScanFS() returned findings when no Docker is installed, got: %v", finding)
	}
}

func TestScanFS_WithIssues(t *testing.T) {
	// Create filesystem with Docker socket and insecure daemon config
	stat := &syscall.Stat_t{
		Uid: 0,
		Gid: 999,
	}

	fsys := fstest.MapFS{
		"etc/docker/daemon.json": &fstest.MapFile{
			Data: []byte(`{"hosts": ["tcp://0.0.0.0:2375"]}`),
		},
	}

	// Custom filesystem with insecure socket permissions
	customFS := &testFS{
		MapFS: fsys,
		sockFile: fakeFile{
			MapFile: &fstest.MapFile{Data: []byte{}},
			info: fakeFileInfo{
				name:    "docker.sock",
				mode:    0666, // world-writable
				modTime: time.Now(),
				sys:     stat,
			},
		},
	}

	d := &Detector{}
	finding, err := d.ScanFS(context.Background(), customFS, &packageindex.PackageIndex{})

	if err != nil {
		t.Errorf("ScanFS() returned error: %v", err)
	}

	if len(finding.GenericFindings) != 1 {
		t.Errorf("ScanFS() expected 1 finding, got %d", len(finding.GenericFindings))
	}

	if finding.GenericFindings[0].Adv.Sev != inventory.SeverityHigh {
		t.Errorf("ScanFS() expected SeverityHigh, got %v", finding.GenericFindings[0].Adv.Sev)
	}
}

func TestDetectorInterface(t *testing.T) {
	d := New()

	if d.Name() != Name {
		t.Errorf("Name() = %q, want %q", d.Name(), Name)
	}

	if d.Version() != 0 {
		t.Errorf("Version() = %d, want 0", d.Version())
	}

	if len(d.RequiredExtractors()) != 0 {
		t.Errorf("RequiredExtractors() = %v, want empty slice", d.RequiredExtractors())
	}

	reqs := d.Requirements()
	if reqs.OS != plugin.OSLinux {
		t.Errorf("Requirements().OS = %q, want %q", reqs.OS, plugin.OSLinux)
	}

	// Test DetectedFinding
	finding := d.DetectedFinding()
	if len(finding.GenericFindings) != 1 {
		t.Errorf("DetectedFinding() expected 1 finding, got %d", len(finding.GenericFindings))
	}

	expectedID := &inventory.AdvisoryID{
		Publisher: "CIS",
		Reference: "docker-socket-exposure",
	}

	if diff := cmp.Diff(expectedID, finding.GenericFindings[0].Adv.ID); diff != "" {
		t.Errorf("DetectedFinding() ID mismatch (-want +got):\n%s", diff)
	}
}
