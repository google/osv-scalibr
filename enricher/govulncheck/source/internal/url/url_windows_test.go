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

// Derived from https://github.com/golang/go/blob/7c2b69080a0b9e35174cc9c93497b6e7176f8275/src/cmd/go/internal/web/url.go
// TODO(golang.org/issue/32456): If accepted, move these functions into the
// net/url package.
//
// Copyright 2023 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.
//go:build windows

package url_test

// Code copied from https://github.com/golang/go/blob/7c2b69080a0b9e35174cc9c93497b6e7176f8275/src/cmd/go/internal/web/url_windows_test.go

var urlTests = []struct {
	url          string
	filePath     string
	canonicalURL string // If empty, assume equal to url.
	wantErr      string
}{
	// Examples from https://blogs.msdn.microsoft.com/ie/2006/12/06/file-uris-in-windows/:

	{
		url:      `file://laptop/My%20Documents/FileSchemeURIs.doc`,
		filePath: `\\laptop\My Documents\FileSchemeURIs.doc`,
	},
	{
		url:      `file:///C:/Documents%20and%20Settings/davris/FileSchemeURIs.doc`,
		filePath: `C:\Documents and Settings\davris\FileSchemeURIs.doc`,
	},
	{
		url:      `file:///D:/Program%20Files/Viewer/startup.htm`,
		filePath: `D:\Program Files\Viewer\startup.htm`,
	},
	{
		url:          `file:///C:/Program%20Files/Music/Web%20Sys/main.html?REQUEST=RADIO`,
		filePath:     `C:\Program Files\Music\Web Sys\main.html`,
		canonicalURL: `file:///C:/Program%20Files/Music/Web%20Sys/main.html`,
	},
	{
		url:      `file://applib/products/a-b/abc_9/4148.920a/media/start.swf`,
		filePath: `\\applib\products\a-b\abc_9\4148.920a\media\start.swf`,
	},
	{
		url:     `file:////applib/products/a%2Db/abc%5F9/4148.920a/media/start.swf`,
		wantErr: "file URL missing drive letter",
	},
	{
		url:     `C:\Program Files\Music\Web Sys\main.html?REQUEST=RADIO`,
		wantErr: "non-file URL",
	},

	// The example "file://D:\Program Files\Viewer\startup.htm" errors out in
	// url.Parse, so we substitute a slash-based path for testing instead.
	{
		url:     `file://D:/Program Files/Viewer/startup.htm`,
		wantErr: "file URL encodes volume in host field: too few slashes?",
	},

	// The blog post discourages the use of non-ASCII characters because they
	// depend on the user's current codepage. However, when we are working with Go
	// strings we assume UTF-8 encoding, and our url package refuses to encode
	// URLs to non-ASCII strings.
	{
		url:          `file:///C:/exampleㄓ.txt`,
		filePath:     `C:\exampleㄓ.txt`,
		canonicalURL: `file:///C:/example%E3%84%93.txt`,
	},
	{
		url:      `file:///C:/example%E3%84%93.txt`,
		filePath: `C:\exampleㄓ.txt`,
	},

	// Examples from RFC 8089:

	// We allow the drive-letter variation from section E.2, because it is
	// simpler to support than not to. However, we do not generate the shorter
	// form in the reverse direction.
	{
		url:          `file:c:/path/to/file`,
		filePath:     `c:\path\to\file`,
		canonicalURL: `file:///c:/path/to/file`,
	},

	// We encode the UNC share name as the authority following section E.3.1,
	// because that is what the Microsoft blog post explicitly recommends.
	{
		url:      `file://host.example.com/Share/path/to/file.txt`,
		filePath: `\\host.example.com\Share\path\to\file.txt`,
	},

	// We decline the four- and five-slash variations from section E.3.2.
	// The paths in these URLs would change meaning under path.Clean.
	{
		url:     `file:////host.example.com/path/to/file`,
		wantErr: "file URL missing drive letter",
	},
	{
		url:     `file://///host.example.com/path/to/file`,
		wantErr: "file URL missing drive letter",
	},
}
