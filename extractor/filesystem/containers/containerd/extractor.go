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

// Package containerd extracts container inventory from containerd metadb database.
package containerd

import (
	"context"
	"encoding/json"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"

	bolt "go.etcd.io/bbolt"
	"github.com/containerd/containerd/metadata"
	"github.com/containerd/containerd/namespaces"
	"github.com/google/osv-scalibr/extractor"
	"github.com/google/osv-scalibr/extractor/filesystem"
	"github.com/google/osv-scalibr/extractor/filesystem/internal/units"
	"github.com/google/osv-scalibr/log"
	"github.com/google/osv-scalibr/purl"
)

const (
	// Name is the unique name of this extractor.
	Name = "containers/containerd"

	// defaultMaxMetaDBFileSize is the maximum metadb size .
	// If Extract gets a bigger metadb file, it will return an error.
	defaultMaxMetaDBFileSize = 500 * units.MiB

	// Prefix of the path for runc state files, used to check if a container is running by runc.
	runcStateFilePrefix = "run/containerd/runc/"
)

// Config is the configuration for the Extractor.
type Config struct {
	// MaxMetaDBFileSize is the maximum file size an extractor will unmarshal.
	// If Extract gets a bigger file, it will return an error.
	MaxMetaDBFileSize int64
}

// DefaultConfig returns the default configuration for the containerd extractor.
func DefaultConfig() Config {
	return Config{
		MaxMetaDBFileSize: defaultMaxMetaDBFileSize,
	}
}

// Extractor extracts containers from the containerd metadb file.
type Extractor struct {
	maxMetaDBFileSize int64
}

// New returns a containerd container inventory extractor.
func New(cfg Config) *Extractor {
	return &Extractor{
		maxMetaDBFileSize: cfg.MaxMetaDBFileSize,
	}
}

// Config returns the configuration of the extractor.
func (e Extractor) Config() Config {
	return Config{
		MaxMetaDBFileSize: e.maxMetaDBFileSize,
	}
}

// Name of the extractor.
func (e Extractor) Name() string { return Name }

// Version of the extractor.
func (e Extractor) Version() int { return 0 }

// FileRequired returns true if the specified file matches containerd metadb file pattern.
func (e Extractor) FileRequired(path string, _ fs.FileInfo) bool {
	// TODO(b/349138656): Add support for containerd inventory for Windows.
	// Only containerd for Linux is supported for now.
	if runtime.GOOS == "windows" {
		return false
	}
	// Matches the containerd expected metadb file path.
	return path == "var/lib/containerd/io.containerd.metadata.v1.bolt/meta.db"
}

// Extract container inventory through the containerd metadb file passed as the scan input.
func (e Extractor) Extract(ctx context.Context, input *filesystem.ScanInput) ([]*extractor.Inventory, error) {
	var inventory = []*extractor.Inventory{}

	if input.Info != nil && input.Info.Size() > e.maxMetaDBFileSize {
		return inventory, fmt.Errorf("Containerd metadb file %s is too large: %d", input.Path, input.Info.Size())
	}

	metaDB, err := bolt.Open(input.Path, 0444, nil)
	if err != nil {
		return inventory, fmt.Errorf("Could not read the containerd metadb file: %v", err)
	}

	defer metaDB.Close()

	ctrMetadata, err := containersFromMetaDB(ctx, metaDB, input.ScanRoot)
	if err != nil {
		log.Errorf("Could not get container inventory from the containerd metadb file: %v", err)
		return inventory, err
	}

	for _, ctr := range ctrMetadata {
		pkg := &extractor.Inventory{
			Name:      ctr.ImageName,
			Version:   ctr.ImageDigest,
			Locations: []string{input.Path},
			Metadata:  &ctr,
		}
		inventory = append(inventory, pkg)
	}

	return inventory, nil
}

func namespacesFromMetaDB(ctx context.Context, metaDB *bolt.DB) ([]string, error) {
	var namespaces []string

	err := metaDB.View(func(tx *bolt.Tx) error {
		store := metadata.NewNamespaceStore(tx)
		nss, err := store.List(ctx)
		if err != nil {
			return err
		}
		namespaces = nss
		return nil
	})

	if err != nil {
		return nil, err
	}

	return namespaces, nil
}

func containersFromMetaDB(ctx context.Context, metaDB *bolt.DB, scanRoot string) ([]Metadata, error) {
	var containersMetadata []Metadata

	// Get list of namespaces from the containerd metadb file.
	nss, err := namespacesFromMetaDB(ctx, metaDB)
	if err != nil {
		return nil, err
	}
	containerdDB := metadata.NewDB(metaDB, nil, nil)
	containerStore := metadata.NewContainerStore(containerdDB)
	imageStore := metadata.NewImageStore(containerdDB)
	for _, ns := range nss {
		// For each namespace stored in the metadb, get the container list to handle.
		ctx = namespaces.WithNamespace(ctx, ns)
		ctrs, err := containerStore.List(ctx)
		if err != nil {
			return nil, err
		}

		// For each container in the namespace
		// get the pid (only running containers will have it) and the image digest.
		for _, ctr := range ctrs {
			var pid int
			id := ctr.ID
			if pid = containerPid(scanRoot, ctr.Runtime.Name, ns, id); pid == -1 {
				continue
			}
			img, err := imageStore.Get(ctx, ctr.Image)
			if err != nil {
				log.Errorf("Could not find the image for container %v, error: %v", id, err)
			}
			containersMetadata = append(containersMetadata,
				Metadata{Namespace: ns,
					ImageName:   img.Name,
					ImageDigest: img.Target.Digest.String(),
					PID:         pid})
		}
	}
	return containersMetadata, nil
}

func containerPid(scanRoot string, runtimeName string, namespace string, id string) int {
	// If container is running by runc, the pid is stored in the runc state.json file.
	// state.json file is located at the
	// <scanRoot>/<runcStateFilePrefix>/<namespace_name>/<container_id>/state.json path.
	if runtimeName != "io.containerd.runc.v2" {
		return -1
	}

	statePath := filepath.Join(scanRoot, runcStateFilePrefix, namespace, id, "state.json")
	if _, err := os.Stat(statePath); err != nil {
		log.Info("File state.json does not exists for container %v, error: %v", id, err)
		return -1
	}

	stateContent, err := os.ReadFile(statePath)
	if err != nil {
		log.Errorf("Could not read for %s state.json for container: %v, error: %v", id, err)
		return -1
	}
	var runcState map[string]*json.RawMessage
	if err := json.Unmarshal([]byte(stateContent), &runcState); err != nil {
		log.Errorf("Can't unmarshal state.json for container %v , error: %v", id, err)
		return -1
	}
	runcPID := runcState["init_process_pid"]
	if runcPID == nil {
		log.Errorf("Can't find field init_process_pid filed in state.json for container %v", id)
		return -1
	}

	var pid int
	if err := json.Unmarshal(*runcPID, &pid); err != nil {
		log.Errorf("Can't find field init_process_pid in state.json for container %v, error: %v", id, err)
		return -1
	}
	return pid
}

// ToPURL converts an inventory created by this extractor into a PURL.
func (e Extractor) ToPURL(i *extractor.Inventory) (*purl.PackageURL, error) { return nil, nil }

// ToCPEs is not applicable as this extractor does not infer CPEs from the Inventory.
func (e Extractor) ToCPEs(i *extractor.Inventory) ([]string, error) { return []string{}, nil }
