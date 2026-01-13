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

package cronjobprivesc

import (
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"strings"
	"syscall"
	"testing"
	"testing/fstest"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/google/osv-scalibr/inventory"
	"github.com/google/osv-scalibr/packageindex"
)

// Helper functions for generating expected test issues

func expectRelativePath(file string, line int, path string) string {
	return fmt.Sprintf("%s:%d: relative path '%s' in privileged cron job - vulnerable to PATH manipulation attack where attacker places malicious executable earlier in PATH", file, line, path)
}

func expectWorldWritableParentDir(file string, line int, parentDir, executablePath string) string {
	return fmt.Sprintf("%s:%d: parent directory '%s' of '%s' is world-writable with execute permission (permissions: 777) - attackers can manipulate path", file, line, parentDir, executablePath)
}

func expectWorldWritableFile(file string, line int, path string) string {
	return fmt.Sprintf("%s:%d: '%s' is world-writable (permissions: 777)", file, line, path)
}

func expectGroupWritableFile(file string, line int, path string, perms fs.FileMode) string {
	return fmt.Sprintf("%s:%d: '%s' is group-writable (permissions: %03o)", file, line, path, perms.Perm())
}

func expectNonRootOwner(file string, line int, path string, uid int) string {
	return fmt.Sprintf("%s:%d: '%s' is not owned by root (uid: %d)", file, line, path, uid)
}

func expectWindowsWritableDir(file, path string) string {
	return fmt.Sprintf("%s: execution from writable directory '%s'", file, path)
}

func expectWindowsRelativePath(file, path string) string {
	return fmt.Sprintf("%s: relative path '%s' in privileged scheduled task - vulnerable to PATH manipulation or DLL hijacking attack", file, path)
}

func expectMacOSRelativePath(file, path string) string {
	return fmt.Sprintf("%s: relative path '%s' in privileged launchd job - vulnerable to PATH manipulation attack", file, path)
}

func expectMacOSInsecureDir(file, path string) string {
	return fmt.Sprintf("%s: execution from insecure directory '%s'", file, path)
}

func extractIssues(finding inventory.Finding) []string {
	var actualIssues []string
	if len(finding.GenericFindings) > 0 {
		extra := finding.GenericFindings[0].Target.Extra
		if extra != "" {
			actualIssues = strings.Split(extra, "\n")
		}
	}
	return actualIssues
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
	if f.offset >= len(f.Data) {
		return 0, io.EOF
	}
	n := copy(b, f.Data[f.offset:])
	f.offset += n
	return n, nil
}

// testFS extends fstest.MapFS to allow custom file info for permission testing
type testFS struct {
	fstest.MapFS

	customFiles map[string]fakeFile
}

func (t *testFS) Open(name string) (fs.File, error) {
	if customFile, exists := t.customFiles[name]; exists {
		// Reset the offset for each read
		customFile.offset = 0
		return &customFile, nil
	}

	// Try without leading slash for custom files
	if nameWithoutSlash, ok := strings.CutPrefix(name, "/"); ok {
		if customFile, exists := t.customFiles[nameWithoutSlash]; exists {
			// Reset the offset for each read
			customFile.offset = 0
			return &customFile, nil
		}
	}

	return t.MapFS.Open(name)
}

func (t *testFS) ReadDir(name string) ([]fs.DirEntry, error) {
	// First get entries from the base MapFS
	entries, err := t.MapFS.ReadDir(name)
	if err != nil && !errors.Is(err, fs.ErrNotExist) {
		return nil, err
	}

	var allEntries []fs.DirEntry
	if err == nil {
		allEntries = entries
	}

	// Add custom files that are in this directory
	for path := range t.customFiles {
		if strings.HasPrefix(path, name+"/") && strings.Count(strings.TrimPrefix(path, name+"/"), "/") == 0 {
			filename := strings.TrimPrefix(path, name+"/")
			// Create a fake DirEntry for this custom file
			allEntries = append(allEntries, &fakeDirEntry{
				name:  filename,
				isDir: false,
				info:  t.customFiles[path].info,
			})
		}
	}

	if len(allEntries) == 0 {
		return nil, fs.ErrNotExist
	}

	return allEntries, nil
}

// fakeDirEntry implements fs.DirEntry
type fakeDirEntry struct {
	name  string
	isDir bool
	info  fakeFileInfo
}

func (f *fakeDirEntry) Name() string {
	return f.name
}

func (f *fakeDirEntry) IsDir() bool {
	return f.isDir
}

func (f *fakeDirEntry) Type() fs.FileMode {
	return f.info.Mode().Type()
}

func (f *fakeDirEntry) Info() (fs.FileInfo, error) {
	return f.info, nil
}

func TestLinuxCronJobs(t *testing.T) {
	tests := []struct {
		name       string
		files      map[string]string
		dirs       map[string]fs.FileMode // directories with their permissions
		wantIssues []string
	}{
		{
			name: "secure crontab - absolute paths only",
			files: map[string]string{
				"etc/crontab": `# System crontab
PATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin

0 0 * * * root /usr/bin/backup.sh
30 2 * * * root /usr/local/bin/cleanup.pl`,
			},
			dirs:       nil,
			wantIssues: nil,
		},
		{
			name: "insecure crontab - relative path",
			files: map[string]string{
				"etc/crontab": `# System crontab
0 0 * * * root backup.sh`,
			},
			dirs:       nil,
			wantIssues: []string{expectRelativePath("etc/crontab", 2, "backup.sh")},
		},
		{
			name: "insecure crontab - execution from /tmp",
			files: map[string]string{
				"etc/crontab": `# System crontab
0 0 * * * root /tmp/malicious_script.sh`,
			},
			dirs: map[string]fs.FileMode{
				"tmp": 0777, // world-writable
			},
			wantIssues: []string{expectWorldWritableParentDir("etc/crontab", 2, "tmp", "/tmp/malicious_script.sh")},
		},
		{
			name: "insecure crontab - execution from /var/tmp",
			files: map[string]string{
				"etc/crontab": `# System crontab
0 0 * * * root /var/tmp/dangerous.py`,
			},
			dirs: map[string]fs.FileMode{
				"var/tmp": 0777, // world-writable
			},
			wantIssues: []string{expectWorldWritableParentDir("etc/crontab", 2, "var/tmp", "/var/tmp/dangerous.py")},
		},
		{
			name: "mixed secure and insecure entries",
			files: map[string]string{
				"etc/crontab": `# System crontab
0 0 * * * root /usr/bin/good_script.sh
30 1 * * * root bad_script.sh
0 2 * * * root /tmp/worse_script.sh`,
			},
			dirs: map[string]fs.FileMode{
				"tmp": 0777, // world-writable
			},
			wantIssues: []string{
				expectRelativePath("etc/crontab", 3, "bad_script.sh"),
				expectWorldWritableParentDir("etc/crontab", 4, "tmp", "/tmp/worse_script.sh"),
			},
		},
		{
			name: "user crontab format without user field",
			files: map[string]string{
				"var/spool/cron/root": `# Root's crontab
0 0 * * * /usr/bin/backup.sh
30 1 * * * relative_script.sh`,
			},
			dirs:       nil,
			wantIssues: []string{expectRelativePath("var/spool/cron/root", 3, "relative_script.sh")},
		},
		{
			name: "cron.d directory with mixed files",
			files: map[string]string{
				"etc/cron.d/backup":    `0 0 * * * root /usr/bin/backup.sh`,
				"etc/cron.d/malicious": `0 0 * * * root /dev/shm/exploit.sh`,
			},
			dirs: map[string]fs.FileMode{
				"dev/shm": 0777, // world-writable
			},
			wantIssues: []string{expectWorldWritableParentDir("etc/cron.d/malicious", 1, "dev/shm", "/dev/shm/exploit.sh")},
		},
		{
			name: "comments and empty lines should be ignored",
			files: map[string]string{
				"etc/crontab": `# This is a comment
# Another comment

# Empty line above
0 0 * * * root /usr/bin/safe_script.sh`,
			},
			dirs:       nil,
			wantIssues: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			testFS := &testFS{
				MapFS:       fstest.MapFS{},
				customFiles: make(map[string]fakeFile),
			}

			// Add files
			for path, content := range tt.files {
				testFS.MapFS[path] = &fstest.MapFile{Data: []byte(content)}
			}

			// Add directories with custom permissions
			for path, mode := range tt.dirs {
				testFS.customFiles[path] = fakeFile{
					info: fakeFileInfo{
						name:  path,
						mode:  fs.ModeDir | mode,
						isDir: true,
					},
				}
			}

			d := &Detector{}
			finding, err := d.ScanFS(context.Background(), testFS, &packageindex.PackageIndex{})

			if err != nil {
				t.Errorf("ScanFS() returned error: %v", err)
			}

			actualIssues := extractIssues(finding)

			if diff := cmp.Diff(tt.wantIssues, actualIssues); diff != "" {
				t.Errorf("Linux cron jobs test mismatch (-want +got):\n%s", diff)
			}
		})
	}
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

func TestWindowsScheduledTasks(t *testing.T) {
	tests := []struct {
		name       string
		tasks      map[string]string
		wantIssues []string
	}{
		{
			name: "secure scheduled task",
			tasks: map[string]string{
				"Windows/System32/Tasks/SecureTask": `<?xml version="1.0"?>
<Task version="1.2">
  <Principals>
    <Principal id="Author">
      <RunLevel>LeastPrivilege</RunLevel>
      <UserId>S-1-5-21-1234567890-1234567890-1234567890-1001</UserId>
    </Principal>
  </Principals>
  <Actions>
    <Exec>
      <Command>C:\Windows\System32\cmd.exe</Command>
      <Arguments>/c "echo secure"</Arguments>
    </Exec>
  </Actions>
</Task>`,
			},
			wantIssues: nil,
		},
		{
			name: "privileged task with relative path",
			tasks: map[string]string{
				"Windows/System32/Tasks/BadTask": `<?xml version="1.0"?>
<Task version="1.2">
  <Principals>
    <Principal id="Author">
      <RunLevel>HighestAvailable</RunLevel>
      <UserId>SYSTEM</UserId>
    </Principal>
  </Principals>
  <Actions>
    <Exec>
      <Command>malicious.exe</Command>
    </Exec>
  </Actions>
</Task>`,
			},
			wantIssues: []string{expectWindowsRelativePath("Windows/System32/Tasks/BadTask", "malicious.exe")},
		},
		{
			name: "system task with execution from temp directory",
			tasks: map[string]string{
				"Windows/System32/Tasks/TempExecution": `<?xml version="1.0"?>
<Task version="1.2">
  <Principals>
    <Principal id="Author">
      <UserId>NT AUTHORITY\SYSTEM</UserId>
    </Principal>
  </Principals>
  <Actions>
    <Exec>
      <Command>C:\Windows\Temp\suspicious.exe</Command>
    </Exec>
  </Actions>
</Task>`,
			},
			wantIssues: []string{expectWindowsWritableDir("Windows/System32/Tasks/TempExecution", "C:\\Windows\\Temp\\suspicious.exe")},
		},
		{
			name: "administrator task with Users\\Public execution",
			tasks: map[string]string{
				"Windows/System32/Tasks/PublicExecution": `<?xml version="1.0"?>
<Task version="1.2">
  <Principals>
    <Principal id="Author">
      <UserId>BUILTIN\\Administrators</UserId>
    </Principal>
  </Principals>
  <Actions>
    <Exec>
      <Command>C:\Users\Public\malware.exe</Command>
    </Exec>
  </Actions>
</Task>`,
			},
			wantIssues: []string{expectWindowsWritableDir("Windows/System32/Tasks/PublicExecution", "C:\\Users\\Public\\malware.exe")},
		},
		{
			name: "nested task directory structure",
			tasks: map[string]string{
				"Windows/System32/Tasks/Microsoft/Windows/BadTask": `<?xml version="1.0"?>
<Task version="1.2">
  <Principals>
    <Principal id="Author">
      <RunLevel>RequireAdministrator</RunLevel>
    </Principal>
  </Principals>
  <Actions>
    <Exec>
      <Command>%TEMP%\exploit.bat</Command>
    </Exec>
  </Actions>
</Task>`,
			},
			wantIssues: []string{expectWindowsWritableDir("Windows/System32/Tasks/Microsoft/Windows/BadTask", "%TEMP%\\exploit.bat")},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fsys := fstest.MapFS{}
			for path, content := range tt.tasks {
				fsys[path] = &fstest.MapFile{Data: []byte(content)}
			}

			d := &Detector{}
			finding, err := d.ScanFS(context.Background(), fsys, &packageindex.PackageIndex{})

			if err != nil {
				t.Errorf("ScanFS() returned error: %v", err)
			}

			actualIssues := extractIssues(finding)

			if diff := cmp.Diff(tt.wantIssues, actualIssues); diff != "" {
				t.Errorf("Windows scheduled tasks test mismatch (-want +got):\n%s", diff)
			}
		})
	}
}

func TestMacOSLaunchd(t *testing.T) {
	tests := []struct {
		name       string
		plists     map[string]string
		wantIssues []string
	}{
		{
			name: "secure launch daemon",
			plists: map[string]string{
				"System/Library/LaunchDaemons/com.example.secure.plist": `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>com.example.secure</string>
    <key>ProgramArguments</key>
    <array>
        <string>/usr/local/bin/secure_daemon</string>
    </array>
</dict>
</plist>`,
			},
			wantIssues: nil,
		},
		{
			name: "launch daemon with relative path",
			plists: map[string]string{
				"Library/LaunchDaemons/com.example.bad.plist": `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>com.example.bad</string>
    <key>ProgramArguments</key>
    <array>
        <string>relative_daemon</string>
    </array>
</dict>
</plist>`,
			},
			wantIssues: []string{expectMacOSRelativePath("Library/LaunchDaemons/com.example.bad.plist", "relative_daemon")},
		},
		{
			name: "launch daemon executing from /tmp",
			plists: map[string]string{
				"System/Library/LaunchDaemons/com.example.tmp.plist": `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>com.example.tmp</string>
    <key>Program</key>
    <string>/tmp/malicious_daemon</string>
    <key>UserName</key>
    <string>root</string>
</dict>
</plist>`,
			},
			wantIssues: []string{expectMacOSInsecureDir("System/Library/LaunchDaemons/com.example.tmp.plist", "/tmp/malicious_daemon")},
		},
		{
			name: "launch daemon executing from Users/Shared",
			plists: map[string]string{
				"Library/LaunchDaemons/com.example.shared.plist": `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>com.example.shared</string>
    <key>ProgramArguments</key>
    <array>
        <string>/Users/Shared/suspicious_binary</string>
    </array>
</dict>
</plist>`,
			},
			wantIssues: []string{expectMacOSInsecureDir("Library/LaunchDaemons/com.example.shared.plist", "/Users/Shared/suspicious_binary")},
		},
		{
			name: "launch agent should not trigger for non-root users",
			plists: map[string]string{
				"Library/LaunchAgents/com.example.user.plist": `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>com.example.user</string>
    <key>ProgramArguments</key>
    <array>
        <string>relative_agent</string>
    </array>
</dict>
</plist>`,
			},
			wantIssues: nil, // LaunchAgents don't run as root by default
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fsys := fstest.MapFS{}
			for path, content := range tt.plists {
				fsys[path] = &fstest.MapFile{Data: []byte(content)}
			}

			d := &Detector{}
			finding, err := d.ScanFS(context.Background(), fsys, &packageindex.PackageIndex{})

			if err != nil {
				t.Errorf("ScanFS() returned error: %v", err)
			}

			actualIssues := extractIssues(finding)

			if diff := cmp.Diff(tt.wantIssues, actualIssues); diff != "" {
				t.Errorf("macOS launchd test mismatch (-want +got):\n%s", diff)
			}
		})
	}
}

func TestScanFS_NoScheduledTasks(t *testing.T) {
	fsys := fstest.MapFS{}

	d := &Detector{}
	finding, err := d.ScanFS(context.Background(), fsys, &packageindex.PackageIndex{})

	if err != nil {
		t.Errorf("ScanFS() returned error: %v", err)
	}

	if len(finding.GenericFindings) != 0 {
		t.Errorf("ScanFS() returned findings when no scheduled tasks exist, got: %v", finding)
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
			name: "comprehensive security issues across platforms",
			setupFS: func() fs.FS {
				testFS := &testFS{
					MapFS: fstest.MapFS{
						// Linux cron issues
						"etc/crontab": &fstest.MapFile{Data: []byte(`0 0 * * * root /tmp/bad_script.sh
30 1 * * * root relative_script.sh`)},
						// Windows task issues
						"Windows/System32/Tasks/BadTask": &fstest.MapFile{Data: []byte(`<?xml version="1.0"?>
<Task version="1.2">
  <Principals>
    <Principal><RunLevel>HighestAvailable</RunLevel><UserId>SYSTEM</UserId></Principal>
  </Principals>
  <Actions>
    <Exec><Command>C:\Temp\malicious.exe</Command></Exec>
  </Actions>
</Task>`)},
						// macOS launchd issues
						"System/Library/LaunchDaemons/com.example.bad.plist": &fstest.MapFile{Data: []byte(`<?xml version="1.0"?>
<plist version="1.0">
<dict>
    <key>ProgramArguments</key>
    <array><string>/var/tmp/suspicious</string></array>
</dict>
</plist>`)},
					},
					customFiles: map[string]fakeFile{
						"tmp": {
							info: fakeFileInfo{
								name:  "tmp",
								mode:  fs.ModeDir | 0777,
								isDir: true,
							},
						},
						"var/tmp": {
							info: fakeFileInfo{
								name:  "var/tmp",
								mode:  fs.ModeDir | 0777,
								isDir: true,
							},
						},
					},
				}
				return testFS
			},
			wantFindingCount: 1,
			wantSeverity:     inventory.SeverityHigh,
			wantIssuesContain: []string{
				"world-writable",
				"relative path",
				"writable directory",
				"insecure directory",
			},
		},
		{
			name: "mixed secure and insecure configurations",
			setupFS: func() fs.FS {
				return fstest.MapFS{
					"etc/crontab": &fstest.MapFile{Data: []byte(`0 0 * * * root /usr/bin/good_script.sh
30 1 * * * root bad_script.sh`)},
				}
			},
			wantFindingCount: 1,
			wantSeverity:     inventory.SeverityHigh,
			wantIssuesContain: []string{
				"relative path 'bad_script.sh'",
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

				extra := finding.GenericFindings[0].Target.Extra
				for _, expectedSubstring := range tt.wantIssuesContain {
					if !strings.Contains(extra, expectedSubstring) {
						t.Errorf("ScanFS() expected issues to contain %q, but got: %s", expectedSubstring, extra)
					}
				}
			}
		})
	}
}

func TestDetectorInterface(t *testing.T) {
	d := New()

	if d.Name() != Name {
		t.Errorf("Name() = %q, want %q", d.Name(), Name)
	}

	finding := d.DetectedFinding()
	if len(finding.GenericFindings) != 1 {
		t.Errorf("DetectedFinding() expected 1 finding, got %d", len(finding.GenericFindings))
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
