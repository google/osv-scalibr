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

package archive_test

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"testing"

	cpb "github.com/google/osv-scalibr/binary/proto/config_go_proto"
	"github.com/google/osv-scalibr/extractor/filesystem"
	"github.com/google/osv-scalibr/extractor/filesystem/embeddedfs/archive"
	"github.com/google/osv-scalibr/extractor/filesystem/embeddedfs/common"
)

// makeTARWithOversizedEntry returns a TAR whose single entry declares a size
// larger than common.MaxTAREntryBytes without containing actual content.
// tar.Writer.Close() returns ErrWriteTooLong here, which we intentionally ignore;
// the header bytes are already in the buffer and that's all we need to exercise
// the per-entry size check in common.TARToTempDir.
func makeTARWithOversizedEntry(t *testing.T) *bytes.Buffer {
	t.Helper()
	buf := &bytes.Buffer{}
	tw := tar.NewWriter(buf)
	hdr := &tar.Header{
		Name:     "bomb.bin",
		Mode:     0600,
		Size:     common.MaxTAREntryBytes + 1,
		Typeflag: tar.TypeReg,
	}
	if err := tw.WriteHeader(hdr); err != nil {
		t.Fatalf("tar.WriteHeader: %v", err)
	}
	// Intentionally omit content bytes; Close will return ErrWriteTooLong but
	// the header is already serialised into buf.
	_ = tw.Close()
	return buf
}

// makeTARGZWithOversizedEntry wraps makeTARWithOversizedEntry in a gzip stream.
func makeTARGZWithOversizedEntry(t *testing.T) *bytes.Buffer {
	t.Helper()
	raw := makeTARWithOversizedEntry(t)
	compressed := &bytes.Buffer{}
	gw := gzip.NewWriter(compressed)
	if _, err := gw.Write(raw.Bytes()); err != nil {
		t.Fatalf("gzip.Write: %v", err)
	}
	if err := gw.Close(); err != nil {
		t.Fatalf("gzip.Close: %v", err)
	}
	return compressed
}

// TestTAREntryOverLimitRejected verifies that a .tar file whose entry declares a
// size exceeding common.MaxTAREntryBytes is rejected before any disk write.
func TestTAREntryOverLimitRejected(t *testing.T) {
	e, err := archive.New(&cpb.PluginConfig{})
	if err != nil {
		t.Fatalf("archive.New(): %v", err)
	}
	input := &filesystem.ScanInput{
		Path:   "test.tar",
		Reader: makeTARWithOversizedEntry(t),
	}
	_, err = e.Extract(t.Context(), input)
	if err == nil {
		t.Fatal("Extract with oversized TAR entry should return an error, got nil")
	}
}

// TestGzippedTAREntryOverLimitRejected verifies that a .tar.gz file whose
// decompressed TAR contains an entry with a declared size exceeding
// common.MaxTAREntryBytes is rejected before any disk write.
// This exercises both the gzip decompression path and the per-entry size guard.
func TestGzippedTAREntryOverLimitRejected(t *testing.T) {
	e, err := archive.New(&cpb.PluginConfig{})
	if err != nil {
		t.Fatalf("archive.New(): %v", err)
	}
	input := &filesystem.ScanInput{
		Path:   "test.tar.gz",
		Reader: makeTARGZWithOversizedEntry(t),
	}
	_, err = e.Extract(t.Context(), input)
	if err == nil {
		t.Fatal("Extract with oversized .tar.gz entry should return an error, got nil")
	}
}
