// Derived from https://github.com/golang/go/blob/7c2b69080a0b9e35174cc9c93497b6e7176f8275/src/cmd/go/internal/web/url.go
// TODO(golang.org/issue/32456): If accepted, move these functions into the
// net/url package.
//
// Copyright 2023 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.
package url_test

import (
	"testing"

	"github.com/google/osv-scalibr/enricher/govulncheck/source/internal/url"
)

// Code copied from https://github.com/golang/go/blob/7c2b69080a0b9e35174cc9c93497b6e7176f8275/src/cmd/go/internal/web/url_test.go

func TestURLFromFilePath(t *testing.T) {
	for _, tc := range urlTests {
		if tc.filePath == "" {
			continue
		}

		t.Run(tc.filePath, func(t *testing.T) {
			u, err := url.FromFilePath(tc.filePath)
			if err != nil {
				if err.Error() == tc.wantErr {
					return
				}
				if tc.wantErr == "" {
					t.Fatalf("urlFromFilePath(%v): %v; want <nil>", tc.filePath, err)
				} else {
					t.Fatalf("urlFromFilePath(%v): %v; want %s", tc.filePath, err, tc.wantErr)
				}
			}

			if tc.wantErr != "" {
				t.Fatalf("urlFromFilePath(%v) = <nil>; want error: %s", tc.filePath, tc.wantErr)
			}

			wantURL := tc.url
			if tc.canonicalURL != "" {
				wantURL = tc.canonicalURL
			}
			if u.String() != wantURL {
				t.Errorf("urlFromFilePath(%v) = %v; want %s", tc.filePath, u, wantURL)
			}
		})
	}
}
