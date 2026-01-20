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

// Package inventory stores the scan result types SCALIBR can return.
package inventory

import (
	"context"

	"github.com/google/osv-scalibr/extractor"
	scalibrfs "github.com/google/osv-scalibr/fs"
)

// Inventory stores the artifacts (e.g. software packages, security findings)
// that a scan found.
type Inventory struct {
	Packages               []*extractor.Package
	PackageVulns           []*PackageVuln
	GenericFindings        []*GenericFinding
	Secrets                []*Secret
	ContainerImageMetadata []*extractor.ContainerImageMetadata
	EmbeddedFSs            []*EmbeddedFS
}

// EmbeddedFS represents a mountable filesystem extracted from
// within another file (e.g., a disk image, partition, or archive).
// This is not proto serialized since it's only used as temporary
// storage to traverse embedded filesystems during extraction.
type EmbeddedFS struct {
	// Path is a unique identifier for the embedded filesystem.
	// It is typically formed by concatenating the path to the source file
	// with the partition index from which the filesystem was extracted.
	Path string

	// TempPaths holds temporary files or directories created during extraction.
	// These should be cleaned up once all extractors, annotators, and detectors
	// have completed their operations.
	// TempPaths will be set when there are temporary directories to clean up.
	TempPaths []string

	// GetEmbeddedFS is a function that mounts or initializes the underlying
	// embedded filesystem and returns a scalibrfs.FS interface for accessing it.
	// The returned filesystem should be closed or cleaned up by the caller
	// when no longer needed.
	GetEmbeddedFS func(context.Context) (scalibrfs.FS, error)
}

// Append adds one or more inventories to the current one.
func (i *Inventory) Append(other ...Inventory) {
	for _, o := range other {
		i.Packages = append(i.Packages, o.Packages...)
		i.PackageVulns = append(i.PackageVulns, o.PackageVulns...)
		i.GenericFindings = append(i.GenericFindings, o.GenericFindings...)
		i.Secrets = append(i.Secrets, o.Secrets...)
		i.ContainerImageMetadata = append(i.ContainerImageMetadata, o.ContainerImageMetadata...)
		i.EmbeddedFSs = append(i.EmbeddedFSs, o.EmbeddedFSs...)
	}
}

// IsEmpty returns true if there are no packages, findings, etc. in this Inventory.
func (i Inventory) IsEmpty() bool {
	if len(i.Packages) != 0 {
		return false
	}
	if len(i.PackageVulns) != 0 {
		return false
	}
	if len(i.GenericFindings) != 0 {
		return false
	}
	if len(i.Secrets) != 0 {
		return false
	}
	if len(i.EmbeddedFSs) != 0 {
		return false
	}
	if len(i.ContainerImageMetadata) != 0 {
		return false
	}
	return true
}
