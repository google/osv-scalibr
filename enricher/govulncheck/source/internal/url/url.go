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

// Derived from https://github.com/golang/go/blob/7c2b69080a0b9e35174cc9c93497b6e7176f8275/src/cmd/go/internal/web/url.go
// TODO(golang.org/issue/32456): If accepted, move these functions into the
// net/url package.
//
// Copyright 2023 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package url creates a url.URL object that is compatible with govulncheck
package url

import (
	"errors"
	"net/url"
	"path/filepath"
	"strings"
)

// ErrNotAbsolute is returned when the input path is not absolute.
var ErrNotAbsolute = errors.New("path is not absolute")

// FromFilePath creates a url.URL object from a file path.
func FromFilePath(path string) (*url.URL, error) {
	if !filepath.IsAbs(path) {
		return nil, ErrNotAbsolute
	}

	// If path has a Windows volume name, convert the volume to a host and prefix
	// per https://blogs.msdn.microsoft.com/ie/2006/12/06/file-uris-in-windows/.
	if vol := filepath.VolumeName(path); vol != "" {
		if strings.HasPrefix(vol, `\\`) {
			path = filepath.ToSlash(path[2:])
			i := strings.IndexByte(path, '/')

			if i < 0 {
				// A degenerate case.
				// \\host.example.com (without a share name)
				// becomes
				// file://host.example.com/
				return &url.URL{
					Scheme: "file",
					Host:   path,
					Path:   "/",
				}, nil
			}

			// \\host.example.com\Share\path\to\file
			// becomes
			// file://host.example.com/Share/path/to/file
			return &url.URL{
				Scheme: "file",
				Host:   path[:i],
				Path:   filepath.ToSlash(path[i:]),
			}, nil
		}

		// C:\path\to\file
		// becomes
		// file:///C:/path/to/file
		return &url.URL{
			Scheme: "file",
			Path:   "/" + filepath.ToSlash(path),
		}, nil
	}

	// /path/to/file
	// becomes
	// file:///path/to/file
	return &url.URL{
		Scheme: "file",
		Path:   filepath.ToSlash(path),
	}, nil
}
