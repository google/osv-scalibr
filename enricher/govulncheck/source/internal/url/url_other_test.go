// Derived from https://github.com/golang/go/blob/7c2b69080a0b9e35174cc9c93497b6e7176f8275/src/cmd/go/internal/web/url.go
// TODO(golang.org/issue/32456): If accepted, move these functions into the
// net/url package.
//
// Copyright 2023 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//go:build !windows

package url_test

// Code copied from https://github.com/golang/go/blob/7c2b69080a0b9e35174cc9c93497b6e7176f8275/src/cmd/go/internal/web/url_other_test.go

var urlTests = []struct {
	url          string
	filePath     string
	canonicalURL string // If empty, assume equal to url.
	wantErr      string
}{
	// Examples from RFC 8089:
	{
		url:      `file:///path/to/file`,
		filePath: `/path/to/file`,
	},
	{
		url:          `file:/path/to/file`,
		filePath:     `/path/to/file`,
		canonicalURL: `file:///path/to/file`,
	},
	{
		url:          `file://localhost/path/to/file`,
		filePath:     `/path/to/file`,
		canonicalURL: `file:///path/to/file`,
	},

	// We reject non-local files.
	{
		url:     `file://host.example.com/path/to/file`,
		wantErr: "file URL specifies non-local host",
	},
}
