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

//go:build linux || darwin

package etcpasswdpermissions_test

import (
	"errors"
	"io/fs"
	"os"
	"syscall"
	"time"
)

func (f *fakeFS) Open(name string) (fs.File, error) {
	if name == "etc/passwd" {
		if f.exists {
			return &fakeFile{perms: f.perms, uid: f.uid, gid: f.gid}, nil
		}
		return nil, os.ErrNotExist
	}
	return nil, errors.New("failed to open")
}
func (fakeFS) ReadDir(name string) ([]fs.DirEntry, error) {
	return nil, errors.New("not implemented")
}
func (fakeFS) Stat(name string) (fs.FileInfo, error) {
	return nil, errors.New("not implemented")
}

func (f *fakeFile) Stat() (fs.FileInfo, error) {
	return &fakeFileInfo{perms: f.perms, uid: f.uid, gid: f.gid}, nil
}
func (fakeFile) Read([]byte) (int, error) { return 0, errors.New("failed to read") }
func (fakeFile) Close() error             { return nil }

func (fakeFileInfo) Name() string         { return "/etc/passwd" }
func (fakeFileInfo) Size() int64          { return 1 }
func (i *fakeFileInfo) Mode() fs.FileMode { return i.perms }
func (fakeFileInfo) ModTime() time.Time   { return time.Now() }
func (i *fakeFileInfo) IsDir() bool       { return false }
func (i *fakeFileInfo) Sys() any          { return &syscall.Stat_t{Uid: i.uid, Gid: i.gid} }
