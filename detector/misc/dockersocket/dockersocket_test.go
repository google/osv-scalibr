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
	"fmt"
	"io"
	"io/fs"
	"runtime"
	"strings"
	"syscall"
	"testing"
	"testing/fstest"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/google/osv-scalibr/inventory"
	"github.com/google/osv-scalibr/packageindex"
	"github.com/google/osv-scalibr/plugin"
)

func init() {
	if runtime.GOOS == "windows" {
		fmt.Printf("Test skipped, OS unsupported: %v\n", runtime.GOOS)
	}
}

// Helper functions for generating expected test issues

func expectSocketWorldReadable(perms fs.FileMode) string {
	return fmt.Sprintf("Docker socket is world-readable (permissions: %03o)", perms.Perm())
}

func expectSocketWorldWritable(perms fs.FileMode) string {
	return fmt.Sprintf("Docker socket is world-writable (permissions: %03o)", perms.Perm())
}

func expectSocketNonRootOwner(uid uint32) string {
	return fmt.Sprintf("Docker socket owner is not root (uid: %d)", uid)
}

func expectInsecureTCPBinding(host string) string {
	return fmt.Sprintf("Insecure TCP binding in daemon.json: %q (consider using TLS)", host)
}

func expectInsecureSystemdBinding(path, line string) string {
	return fmt.Sprintf("Insecure TCP binding in %q: %q (missing TLS)", path, line)
}

// fakeFileInfo implements fs.FileInfo for testing
type fakeFileInfo struct {
	name    string
	size    int64
	mode    fs.FileMode
	modTime time.Time
	isDir   bool
	sys     any
}

func (f fakeFileInfo) Name() string       { return f.name }
func (f fakeFileInfo) Size() int64        { return f.size }
func (f fakeFileInfo) Mode() fs.FileMode  { return f.mode }
func (f fakeFileInfo) ModTime() time.Time { return f.modTime }
func (f fakeFileInfo) IsDir() bool        { return f.isDir }
func (f fakeFileInfo) Sys() any           { return f.sys }

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
		wantIssues  []string
	}{
		{
			name:        "secure socket permissions",
			socketPerms: 0660, // rw-rw----
			uid:         0,    // root
			gid:         999,  // docker group
			wantIssues:  nil,
		},
		{
			name:        "world-readable socket",
			socketPerms: 0664, // rw-rw-r--
			uid:         0,
			gid:         999,
			wantIssues:  []string{expectSocketWorldReadable(0664)},
		},
		{
			name:        "world-writable socket",
			socketPerms: 0666, // rw-rw-rw-
			uid:         0,
			gid:         999,
			wantIssues:  []string{expectSocketWorldReadable(0666), expectSocketWorldWritable(0666)},
		},
		{
			name:        "non-root owner",
			socketPerms: 0660,
			uid:         1000, // non-root
			gid:         999,
			wantIssues:  []string{expectSocketNonRootOwner(1000)},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			stat := &syscall.Stat_t{
				Uid: tt.uid,
				Gid: tt.gid,
			}

			fsys := fstest.MapFS{}

			// Override the file with our custom info
			file := fakeFile{
				MapFile: &fstest.MapFile{Data: []byte{}},
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
			finding, err := d.ScanFS(context.Background(), customFS, &packageindex.PackageIndex{})

			if err != nil {
				t.Errorf("ScanFS() returned error: %v", err)
			}

			var actualIssues []string
			if len(finding.GenericFindings) > 0 {
				// Extract issues from the Extra field
				extra := finding.GenericFindings[0].Target.Extra
				if extra != "" {
					actualIssues = strings.Split(extra, "; ")
				}
			}

			// Filter to only socket-related issues for this test
			var socketIssues []string
			for _, issue := range actualIssues {
				if strings.Contains(issue, "Docker socket") {
					socketIssues = append(socketIssues, issue)
				}
			}

			if diff := cmp.Diff(tt.wantIssues, socketIssues); diff != "" {
				t.Errorf("Socket permissions test mismatch (-want +got):\n%s", diff)
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
		wantIssues []string
	}{
		{
			name:       "secure config - no hosts",
			config:     `{}`,
			wantIssues: nil,
		},
		{
			name:       "secure config - unix socket only",
			config:     `{"hosts": ["unix:///var/run/docker.sock"]}`,
			wantIssues: nil,
		},
		{
			name:       "insecure config - tcp without tls",
			config:     `{"hosts": ["tcp://0.0.0.0:2375"]}`,
			wantIssues: []string{expectInsecureTCPBinding("tcp://0.0.0.0:2375")},
		},
		{
			name:       "mixed config - both secure and insecure",
			config:     `{"hosts": ["unix:///var/run/docker.sock", "tcp://0.0.0.0:2375"]}`,
			wantIssues: []string{expectInsecureTCPBinding("tcp://0.0.0.0:2375")},
		},
		{
			name:       "multiple insecure hosts",
			config:     `{"hosts": ["tcp://0.0.0.0:2375", "tcp://127.0.0.1:2376"]}`,
			wantIssues: []string{expectInsecureTCPBinding("tcp://0.0.0.0:2375"), expectInsecureTCPBinding("tcp://127.0.0.1:2376")},
		},
		{
			name:       "invalid json",
			config:     `{invalid json}`,
			wantIssues: nil, // Should not error on invalid JSON
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
			finding, err := d.ScanFS(context.Background(), fsys, &packageindex.PackageIndex{})

			if err != nil {
				t.Errorf("ScanFS() returned error: %v", err)
			}

			var actualIssues []string
			if len(finding.GenericFindings) > 0 {
				// Extract issues from the Extra field
				extra := finding.GenericFindings[0].Target.Extra
				if extra != "" {
					actualIssues = strings.Split(extra, "; ")
				}
			}

			// Filter to only daemon config related issues for this test
			var daemonIssues []string
			for _, issue := range actualIssues {
				if strings.Contains(issue, "daemon.json") {
					daemonIssues = append(daemonIssues, issue)
				}
			}

			if diff := cmp.Diff(tt.wantIssues, daemonIssues); diff != "" {
				t.Errorf("Daemon config test mismatch (-want +got):\n%s", diff)
			}
		})
	}
}

func TestSystemdServiceConfig(t *testing.T) {
	tests := []struct {
		name        string
		serviceFile string
		wantIssues  []string
	}{
		{
			name: "secure service - unix socket only",
			serviceFile: `[Unit]
Description=Docker Application Container Engine

[Service]
ExecStart=/usr/bin/dockerd -H unix:///var/run/docker.sock

[Install]
WantedBy=multi-user.target`,
			wantIssues: nil,
		},
		{
			name: "insecure service - tcp without tls",
			serviceFile: `[Unit]
Description=Docker Application Container Engine

[Service]
ExecStart=/usr/bin/dockerd -H tcp://0.0.0.0:2375

[Install]
WantedBy=multi-user.target`,
			wantIssues: []string{expectInsecureSystemdBinding("etc/systemd/system/docker.service", "ExecStart=/usr/bin/dockerd -H tcp://0.0.0.0:2375")},
		},
		{
			name: "secure service - tcp with tls",
			serviceFile: `[Unit]
Description=Docker Application Container Engine

[Service]
ExecStart=/usr/bin/dockerd -H tcp://0.0.0.0:2376 --tls --tlscert=/path/to/cert.pem --tlskey=/path/to/key.pem

[Install]
WantedBy=multi-user.target`,
			wantIssues: nil,
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
			wantIssues: []string{expectInsecureSystemdBinding("etc/systemd/system/docker.service", "ExecStart=/usr/bin/dockerd -H tcp://0.0.0.0:2375")},
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
			finding, err := d.ScanFS(context.Background(), fsys, &packageindex.PackageIndex{})

			if err != nil {
				t.Errorf("ScanFS() returned error: %v", err)
			}

			var actualIssues []string
			if len(finding.GenericFindings) > 0 {
				// Extract issues from the Extra field
				extra := finding.GenericFindings[0].Target.Extra
				if extra != "" {
					actualIssues = strings.Split(extra, "; ")
				}
			}

			// Filter to only systemd service related issues for this test
			var systemdIssues []string
			for _, issue := range actualIssues {
				if strings.Contains(issue, "systemd") || strings.Contains(issue, ".service") {
					systemdIssues = append(systemdIssues, issue)
				}
			}

			if diff := cmp.Diff(tt.wantIssues, systemdIssues); diff != "" {
				t.Errorf("Systemd service test mismatch (-want +got):\n%s", diff)
			}
		})
	}
}

func TestSystemdServiceConfig_MultiplePaths(t *testing.T) {
	// Test that the detector checks all possible systemd service paths
	insecureService := `[Unit]
Description=Docker Application Container Engine

[Service]
ExecStart=/usr/bin/dockerd -H tcp://0.0.0.0:2375

[Install]
WantedBy=multi-user.target`

	tests := []struct {
		name       string
		files      map[string]string
		wantIssues []string
	}{
		{
			name: "service in /etc/systemd/system",
			files: map[string]string{
				"etc/systemd/system/docker.service": insecureService,
			},
			wantIssues: []string{expectInsecureSystemdBinding("etc/systemd/system/docker.service", "ExecStart=/usr/bin/dockerd -H tcp://0.0.0.0:2375")},
		},
		{
			name: "service in /lib/systemd/system",
			files: map[string]string{
				"lib/systemd/system/docker.service": `[Service]
ExecStart=/usr/bin/dockerd -H tcp://127.0.0.1:2376`,
			},
			wantIssues: []string{expectInsecureSystemdBinding("lib/systemd/system/docker.service", "ExecStart=/usr/bin/dockerd -H tcp://127.0.0.1:2376")},
		},
		{
			name: "service in /usr/lib/systemd/system",
			files: map[string]string{
				"usr/lib/systemd/system/docker.service": `[Service]
ExecStart=/usr/bin/dockerd -H tcp://192.168.1.1:2377`,
			},
			wantIssues: []string{expectInsecureSystemdBinding("usr/lib/systemd/system/docker.service", "ExecStart=/usr/bin/dockerd -H tcp://192.168.1.1:2377")},
		},
		{
			name: "multiple service files with issues",
			files: map[string]string{
				"etc/systemd/system/docker.service": insecureService,
				"lib/systemd/system/docker.service": `[Service]
ExecStart=/usr/bin/dockerd -H tcp://10.0.0.1:2378`,
			},
			wantIssues: []string{
				expectInsecureSystemdBinding("etc/systemd/system/docker.service", "ExecStart=/usr/bin/dockerd -H tcp://0.0.0.0:2375"),
				expectInsecureSystemdBinding("lib/systemd/system/docker.service", "ExecStart=/usr/bin/dockerd -H tcp://10.0.0.1:2378"),
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fsys := fstest.MapFS{}
			for path, content := range tt.files {
				fsys[path] = &fstest.MapFile{Data: []byte(content)}
			}

			d := &Detector{}
			finding, err := d.ScanFS(context.Background(), fsys, &packageindex.PackageIndex{})

			if err != nil {
				t.Errorf("ScanFS() returned error: %v", err)
			}

			var actualIssues []string
			if len(finding.GenericFindings) > 0 {
				// Extract issues from the Extra field
				extra := finding.GenericFindings[0].Target.Extra
				if extra != "" {
					actualIssues = strings.Split(extra, "; ")
				}
			}

			// Filter to only systemd service related issues for this test
			var systemdIssues []string
			for _, issue := range actualIssues {
				if strings.Contains(issue, "systemd") || strings.Contains(issue, ".service") {
					systemdIssues = append(systemdIssues, issue)
				}
			}

			if diff := cmp.Diff(tt.wantIssues, systemdIssues); diff != "" {
				t.Errorf("Multiple paths test mismatch (-want +got):\n%s", diff)
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

func TestScanFS_Integration(t *testing.T) {
	tests := []struct {
		name              string
		setupFS           func() fs.FS
		wantFindingCount  int
		wantSeverity      inventory.SeverityEnum
		wantIssuesContain []string
	}{
		{
			name: "socket with world-readable and insecure daemon config",
			setupFS: func() fs.FS {
				stat := &syscall.Stat_t{Uid: 0, Gid: 999}
				fsys := fstest.MapFS{
					"etc/docker/daemon.json": &fstest.MapFile{
						Data: []byte(`{"hosts": ["tcp://0.0.0.0:2375"]}`),
					},
				}
				return &testFS{
					MapFS: fsys,
					sockFile: fakeFile{
						MapFile: &fstest.MapFile{Data: []byte{}},
						info: fakeFileInfo{
							name:    "docker.sock",
							mode:    0664, // world-readable
							modTime: time.Now(),
							sys:     stat,
						},
					},
				}
			},
			wantFindingCount: 1,
			wantSeverity:     inventory.SeverityHigh,
			wantIssuesContain: []string{
				"Docker socket is world-readable",
				"Insecure TCP binding in daemon.json",
			},
		},
		{
			name: "multiple insecure systemd services",
			setupFS: func() fs.FS {
				insecureService := `[Service]
ExecStart=/usr/bin/dockerd -H tcp://0.0.0.0:2375`
				return fstest.MapFS{
					"etc/systemd/system/docker.service": &fstest.MapFile{Data: []byte(insecureService)},
					"lib/systemd/system/docker.service": &fstest.MapFile{Data: []byte(insecureService)},
				}
			},
			wantFindingCount: 1,
			wantSeverity:     inventory.SeverityHigh,
			wantIssuesContain: []string{
				"Insecure TCP binding in \"etc/systemd/system/docker.service\"",
				"Insecure TCP binding in \"lib/systemd/system/docker.service\"",
			},
		},
		{
			name: "comprehensive security issues",
			setupFS: func() fs.FS {
				stat := &syscall.Stat_t{Uid: 1000, Gid: 999} // non-root owner
				fsys := fstest.MapFS{
					"etc/docker/daemon.json": &fstest.MapFile{
						Data: []byte(`{"hosts": ["tcp://0.0.0.0:2375", "tcp://127.0.0.1:2376"]}`),
					},
					"etc/systemd/system/docker.service": &fstest.MapFile{
						Data: []byte(`[Service]
ExecStart=/usr/bin/dockerd -H tcp://0.0.0.0:2377`),
					},
				}
				return &testFS{
					MapFS: fsys,
					sockFile: fakeFile{
						MapFile: &fstest.MapFile{Data: []byte{}},
						info: fakeFileInfo{
							name:    "docker.sock",
							mode:    0666, // world-readable and writable
							modTime: time.Now(),
							sys:     stat,
						},
					},
				}
			},
			wantFindingCount: 1,
			wantSeverity:     inventory.SeverityHigh,
			wantIssuesContain: []string{
				"Docker socket is world-readable",
				"Docker socket is world-writable",
				"Docker socket owner is not root",
				"tcp://0.0.0.0:2375",
				"tcp://127.0.0.1:2376",
				"tcp://0.0.0.0:2377",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			d := &Detector{}
			finding, err := d.ScanFS(context.Background(), tt.setupFS(), &packageindex.PackageIndex{})

			if err != nil {
				t.Errorf("ScanFS() returned error: %v", err)
			}

			if len(finding.GenericFindings) != tt.wantFindingCount {
				t.Errorf("ScanFS() expected %d findings, got %d", tt.wantFindingCount, len(finding.GenericFindings))
			}

			if tt.wantFindingCount > 0 && len(finding.GenericFindings) > 0 {
				if finding.GenericFindings[0].Adv.Sev != tt.wantSeverity {
					t.Errorf("ScanFS() expected %v severity, got %v", tt.wantSeverity, finding.GenericFindings[0].Adv.Sev)
				}

				// Check that all expected issue substrings are present in the target extra field
				extra := finding.GenericFindings[0].Target.Extra
				for _, expectedSubstring := range tt.wantIssuesContain {
					if !contains(extra, expectedSubstring) {
						t.Errorf("ScanFS() expected issues to contain %q, but got: %s", expectedSubstring, extra)
					}
				}
			}
		})
	}
}

// Helper function to check if a string contains a substring
func contains(s, substr string) bool {
	return strings.Contains(s, substr)
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
	if reqs.OS != plugin.OSUnix {
		t.Errorf("Requirements().OS = %q, want %q", reqs.OS, plugin.OSUnix)
	}

	// Test DetectedFinding
	finding := d.DetectedFinding()
	if len(finding.GenericFindings) != 1 {
		t.Errorf("DetectedFinding() expected 1 finding, got %d", len(finding.GenericFindings))
	}

	expectedID := &inventory.AdvisoryID{
		Publisher: "SCALIBR",
		Reference: "docker-socket-exposure",
	}

	if diff := cmp.Diff(expectedID, finding.GenericFindings[0].Adv.ID); diff != "" {
		t.Errorf("DetectedFinding() ID mismatch (-want +got):\n%s", diff)
	}
}
