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

//go:build !linux && !darwin

package etcpasswdpermissions_test

import (
	"errors"
	"io/fs"
	"time"
)

func (fakeFS) Open(name string) (fs.File, error) { return nil, errors.New("unsupported system") }
func (fakeFS) ReadDir(name string) ([]fs.DirEntry, error) {
	return nil, errors.New("not implemented")
}
func (fakeFS) Stat(name string) (fs.FileInfo, error) {
	return nil, errors.New("not implemented")
}
func (fakeFile) Stat() (fs.FileInfo, error) { return nil, errors.New("unsupported system") }
func (fakeFile) Read([]byte) (int, error)   { return 0, errors.New("unsupported system") }
func (fakeFile) Close() error               { return nil }

func (fakeFileInfo) Name() string       { return "unsupported" }
func (fakeFileInfo) Size() int64        { return 0 }
func (fakeFileInfo) Mode() fs.FileMode  { return 0 }
func (fakeFileInfo) ModTime() time.Time { return time.Now() }
func (fakeFileInfo) IsDir() bool        { return false }
func (fakeFileInfo) Sys() any           { return nil }
