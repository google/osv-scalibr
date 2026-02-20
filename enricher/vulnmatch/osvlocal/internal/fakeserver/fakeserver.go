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

// Package fakeserver contains test helpers for serving OSVs in zip files
package fakeserver

import (
	"archive/zip"
	"bytes"
	"encoding/base64"
	"encoding/binary"
	"hash/crc32"
	"net/http"
	"net/http/httptest"
	"testing"

	osvpb "github.com/ossf/osv-schema/bindings/go/osvschema"
	"google.golang.org/protobuf/encoding/protojson"
)

// CreateZipServer setups up a new httptest.Server
func CreateZipServer(t *testing.T, handler http.HandlerFunc) *httptest.Server {
	t.Helper()

	ts := httptest.NewServer(handler)

	t.Cleanup(ts.Close)

	return ts
}

// ComputeCRC32CHash computes the CRC32 hash for the given data
func ComputeCRC32CHash(t *testing.T, data []byte) string {
	t.Helper()

	hash := crc32.Checksum(data, crc32.MakeTable(crc32.Castagnoli))

	return base64.StdEncoding.EncodeToString(binary.BigEndian.AppendUint32([]byte{}, hash))
}

// WriteOSVsZip writes a zipfile containing the given OVSs to the response writer,
// along with setting the x-goog-hash with the crc32 hash of the file
func WriteOSVsZip(t *testing.T, w http.ResponseWriter, osvs map[string]*osvpb.Vulnerability) (int, error) {
	t.Helper()

	z := ZipOSVs(t, osvs)

	w.Header().Add("X-Goog-Hash", "crc32c="+ComputeCRC32CHash(t, z))

	return w.Write(z)
}

// ZipOSVs creates a new in-memory zip file containing the given osvs
func ZipOSVs(t *testing.T, osvs map[string]*osvpb.Vulnerability) []byte {
	t.Helper()

	buf := new(bytes.Buffer)
	writer := zip.NewWriter(buf)

	for fp, osv := range osvs {
		data, err := protojson.Marshal(osv)
		if err != nil {
			t.Fatalf("could not marshal %v: %v", osv, err)
		}

		f, err := writer.Create(fp)
		if err != nil {
			t.Fatal(err)
		}
		_, err = f.Write(data)
		if err != nil {
			t.Fatal(err)
		}
	}

	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}

	return buf.Bytes()
}
