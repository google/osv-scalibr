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

//go:build linux

package containerd

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestGetImageDiffIDs(t *testing.T) {
	d := t.TempDir()

	indexDigest := "sha256:1111111111111111111111111111111111111111111111111111111111111111"
	indexJSON := "{\"manifests\": [{\"digest\": \"sha256:2222222222222222222222222222222222222222222222222222222222222222\",\"platform\": {\"architecture\": \"arm64\",\"os\": \"linux\"}}]}"

	// Write the index blob
	blobDir := filepath.Join(d, "var/lib/containerd/io.containerd.content.v1.content/blobs/sha256")
	if err := os.MkdirAll(blobDir, 0755); err != nil {
		t.Fatalf("MkdirAll failed: %v", err)
	}
	if err := os.WriteFile(filepath.Join(blobDir, "1111111111111111111111111111111111111111111111111111111111111111"), []byte(indexJSON), 0644); err != nil {
		t.Fatalf("WriteFile failed: %v", err)
	}

	// Write an invalid inner manifest blob
	if err := os.WriteFile(filepath.Join(blobDir, "2222222222222222222222222222222222222222222222222222222222222222"), []byte("{bad json"), 0644); err != nil {
		t.Fatalf("WriteFile failed: %v", err)
	}

	// Test: Fallback triggers and then errors on bad JSON
	_, err := getImageDiffIDs(d, indexDigest)
	if err == nil {
		t.Errorf("getImageDiffIDs() expected error on invalid json, got nil")
	} else if fmt.Sprintf("%v", err) != "could not parse inner manifest blob: invalid character 'b' looking for beginning of object key string" && fmt.Sprintf("%v", err) != "could not parse inner manifest blob: unexpected end of JSON input" {
		t.Errorf("getImageDiffIDs() unexpected error: %v", err)
	}
}

func TestCollectGcfsDirs(t *testing.T) {
	d := t.TempDir()
	snapshotKey := "my-snapshot-key"
	manifestDigest := "sha256:1111111111111111111111111111111111111111111111111111111111111111"

	// Write mock config blob so getImageDiffIDs succeeds
	configJSON := `{"rootfs": {"diff_ids": ["sha256:1234567890abcdef"]}}`
	manifestJSON := `{"config": {"digest": "sha256:2222222222222222222222222222222222222222222222222222222222222222"}}`

	blobDir := filepath.Join(d, "var/lib/containerd/io.containerd.content.v1.content/blobs/sha256")
	if err := os.MkdirAll(blobDir, 0755); err != nil {
		t.Fatalf("MkdirAll failed: %v", err)
	}
	if err := os.WriteFile(filepath.Join(blobDir, "1111111111111111111111111111111111111111111111111111111111111111"), []byte(manifestJSON), 0644); err != nil {
		t.Fatalf("WriteFile failed: %v", err)
	}
	if err := os.WriteFile(filepath.Join(blobDir, "2222222222222222222222222222222222222222222222222222222222222222"), []byte(configJSON), 0644); err != nil {
		t.Fatalf("WriteFile failed: %v", err)
	}

	snapshotsMetadata := []SnapshotMetadata{
		{
			ID:     2,
			Digest: "my-snapshot-key",
		},
	}

	lowerDir, upperDir, workDir := collectGcfsDirs(d, snapshotsMetadata, snapshotKey, manifestDigest, "test-container-id")

	wantLower := filepath.Join(d, "var/lib/containerd/io.containerd.snapshotter.v1.gcfs/snapshotter/layers/sha256=1234567890abcdef")
	if lowerDir != wantLower {
		t.Errorf("lowerDir = %v, want %v", lowerDir, wantLower)
	}

	wantUpper := filepath.Join(d, "var/lib/containerd/io.containerd.snapshotter.v1.gcfs/snapshotter/snapshots/2/fs")
	if upperDir != wantUpper {
		t.Errorf("upperDir = %v, want %v", upperDir, wantUpper)
	}

	wantWork := filepath.Join(d, "var/lib/containerd/io.containerd.snapshotter.v1.gcfs/snapshotter/snapshots/2/work")
	if workDir != wantWork {
		t.Errorf("workDir = %v, want %v", workDir, wantWork)
	}
}

func TestGetImageDiffIDsAmd64Fallback(t *testing.T) {
	d := t.TempDir()

	indexDigest := "sha256:1111111111111111111111111111111111111111111111111111111111111111"
	indexJSON := `{"manifests": [{"digest": "sha256:2222222222222222222222222222222222222222222222222222222222222222","platform": {"architecture": "arm64","os": "linux"}}, {"digest": "sha256:3333333333333333333333333333333333333333333333333333333333333333","platform": {"architecture": "amd64","os": "linux"}}]}`

	// Write the index blob
	blobDir := filepath.Join(d, "var/lib/containerd/io.containerd.content.v1.content/blobs/sha256")
	if err := os.MkdirAll(blobDir, 0755); err != nil {
		t.Fatalf("MkdirAll failed: %v", err)
	}
	if err := os.WriteFile(filepath.Join(blobDir, "1111111111111111111111111111111111111111111111111111111111111111"), []byte(indexJSON), 0644); err != nil {
		t.Fatalf("WriteFile failed: %v", err)
	}

	if err := os.WriteFile(filepath.Join(blobDir, "3333333333333333333333333333333333333333333333333333333333333333"), []byte("{bad json"), 0644); err != nil {
		t.Fatalf("WriteFile failed: %v", err)
	}

	_, err := getImageDiffIDs(d, indexDigest)
	if err == nil {
		t.Errorf("getImageDiffIDs() expected error on invalid json, got nil")
	} else if fmt.Sprintf("%v", err) != "could not parse inner manifest blob: invalid character 'b' looking for beginning of object key string" && fmt.Sprintf("%v", err) != "could not parse inner manifest blob: unexpected end of JSON input" {
		t.Errorf("getImageDiffIDs() unexpected error: %v", err)
	}
}

func TestGetImageDiffIDsUnmarshalError(t *testing.T) {
	d := t.TempDir()
	indexDigest := "sha256:1111111111111111111111111111111111111111111111111111111111111111"

	// Write an invalid blob so both unmarshals fail
	blobDir := filepath.Join(d, "var/lib/containerd/io.containerd.content.v1.content/blobs/sha256")
	if err := os.MkdirAll(blobDir, 0755); err != nil {
		t.Fatalf("MkdirAll failed: %v", err)
	}
	if err := os.WriteFile(filepath.Join(blobDir, "1111111111111111111111111111111111111111111111111111111111111111"), []byte("{bad json"), 0644); err != nil {
		t.Fatalf("WriteFile failed: %v", err)
	}

	_, err := getImageDiffIDs(d, indexDigest)
	if err == nil {
		t.Errorf("expected error on invalid json blob, got nil")
	} else if !strings.Contains(err.Error(), "could not parse blob as either index or manifest") {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestDigestSnapshotInfoMapping(t *testing.T) {
	snapshotsMetadataOverlay := []SnapshotMetadata{
		{
			Digest:         "sha256:12345/digest1",
			FilesystemType: "overlayfs",
		},
		{
			Digest:         "invalid_digest_no_slash",
			FilesystemType: "overlayfs",
		},
		{
			Digest:         "invalid_digest_trailing_slash/",
			FilesystemType: "overlayfs",
		},
	}

	// Test overlayfs
	resultOverlay := digestSnapshotInfoMapping(snapshotsMetadataOverlay)
	if len(resultOverlay) != 1 {
		t.Errorf("Expected 1 result for overlayfs, got %d", len(resultOverlay))
	}
	if _, ok := resultOverlay["digest1"]; !ok {
		t.Errorf("Expected result to contain 'digest1'")
	}

	// Test gcfs
	snapshotsMetadataGcfs := []SnapshotMetadata{
		{
			Digest:         "sha256:67890/digest2",
			FilesystemType: "gcfs",
		},
	}
	resultGcfs := digestSnapshotInfoMapping(snapshotsMetadataGcfs)
	if len(resultGcfs) != 1 {
		t.Errorf("Expected 1 result for gcfs, got %d", len(resultGcfs))
	}
	if _, ok := resultGcfs["digest2"]; !ok {
		t.Errorf("Expected result to contain 'digest2'")
	}
}
