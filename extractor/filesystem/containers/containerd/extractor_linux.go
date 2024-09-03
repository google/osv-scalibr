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

//go:build linux

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
	"strconv"
	"strings"
	"time"

	bolt "go.etcd.io/bbolt"
	"github.com/containerd/containerd/metadata"
	"github.com/containerd/containerd/namespaces"
	"github.com/google/osv-scalibr/extractor"
	"github.com/google/osv-scalibr/extractor/filesystem"
	"github.com/google/osv-scalibr/extractor/filesystem/internal/units"
	"github.com/google/osv-scalibr/log"
	"github.com/google/osv-scalibr/plugin"
	"github.com/google/osv-scalibr/purl"
)

const (
	// Name is the unique name of this extractor.
	Name = "containers/containerd"

	// defaultMaxMetaDBFileSize is the maximum metadb size.
	// If Extract gets a bigger metadb file, it will return an error.
	defaultMaxMetaDBFileSize = 500 * units.MiB

	// defaultMaxStateJsonFileSize is the maximum state.json size.
	// If Extract gets a bigger state.json file, it will return an error.
	defaultMaxStateJSONFileSize = 5 * units.MiB

	// Prefix of the path for runc state files, used to check if a container is running by runc.
	runcStateFilePrefix = "run/containerd/runc/"

	// Prefix of the path for runhcs state files, used to check if a container is running by runhcs.
	runhcsStateFilePrefix = "ProgramData/containerd/state/io.containerd.runtime.v2.task/"
)

// Config is the configuration for the Extractor.
type Config struct {
	// MaxMetaDBFileSize is the maximum file size an extractor will unmarshal.
	// If Extract gets a bigger file, it will return an error.
	MaxMetaDBFileSize    int64
	MaxStateJSONFileSize int64
}

// DefaultConfig returns the default configuration for the containerd extractor.
func DefaultConfig() Config {
	return Config{
		MaxMetaDBFileSize:    defaultMaxMetaDBFileSize,
		MaxStateJSONFileSize: defaultMaxStateJSONFileSize,
	}
}

// Extractor extracts containers from the containerd metadb file.
type Extractor struct {
	maxMetaDBFileSize    int64
	maxStateJSONFileSize int64
}

// New returns a containerd container inventory extractor.
func New(cfg Config) *Extractor {
	return &Extractor{
		maxMetaDBFileSize:    cfg.MaxMetaDBFileSize,
		maxStateJSONFileSize: cfg.MaxStateJSONFileSize,
	}
}

// Config returns the configuration of the extractor.
func (e Extractor) Config() Config {
	return Config{
		MaxMetaDBFileSize:    e.maxMetaDBFileSize,
		MaxStateJSONFileSize: e.maxStateJSONFileSize,
	}
}

// Name of the extractor.
func (e Extractor) Name() string { return Name }

// Version of the extractor.
func (e Extractor) Version() int { return 0 }

// Requirements of the extractor.
func (e Extractor) Requirements() *plugin.Capabilities { return &plugin.Capabilities{DirectFS: true} }

// FileRequired returns true if the specified file matches containerd metadb file pattern.
func (e Extractor) FileRequired(path string, _ fs.FileInfo) bool {
	// On Windows the metadb file is expected to be located at the
	// <scanRoot>/ProgramData/containerd/root/io.containerd.metadata.v1.bolt/meta.db path.
	switch runtime.GOOS {
	case "windows":
		return path == "ProgramData/containerd/root/io.containerd.metadata.v1.bolt/meta.db"

	// On Linux the metadb file is expected to be located at the
	// <scanRoot>/var/lib/containerd/io.containerd.metadata.v1.bolt/meta.db path.
	default:
		return path == "var/lib/containerd/io.containerd.metadata.v1.bolt/meta.db"
	}
}

// Extract container inventory through the containerd metadb file passed as the scan input.
func (e Extractor) Extract(ctx context.Context, input *filesystem.ScanInput) ([]*extractor.Inventory, error) {
	var inventory = []*extractor.Inventory{}

	if input.Info != nil && input.Info.Size() > e.maxMetaDBFileSize {
		return inventory, fmt.Errorf("Containerd metadb file %s is too large: %d", input.Path, input.Info.Size())
	}

	// Timeout is added to make sure Scalibr does not hand if the metadb file is open by another process.
	// This will still allow to handle the snapshot of a machine.
	metaDB, err := bolt.Open(filepath.Join(input.Root, input.Path), 0444, &bolt.Options{Timeout: 1 * time.Second})
	if err != nil {
		return inventory, fmt.Errorf("Could not read the containerd metadb file: %v", err)
	}

	defer metaDB.Close()

	ctrMetadata, err := containersFromMetaDB(ctx, metaDB, input.Root, e.maxStateJSONFileSize)
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

func containersFromMetaDB(ctx context.Context, metaDB *bolt.DB, scanRoot string, maxStateJSONFileSize int64) ([]Metadata, error) {
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
		// get the init process pid (only running containers will have it stored on the file system)
		// and the image digest.
		for _, ctr := range ctrs {
			var initPID int
			id := ctr.ID
			var rootfs string
			if initPID, rootfs = containerInitPidAndRootfs(scanRoot, ctr.Runtime.Name, ns, id, maxStateJSONFileSize); initPID == -1 {
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
					Runtime:     ctr.Runtime.Name,
					PID:         initPID,
					RootFS:      rootfs,
					ID:          ctr.ID})
		}
	}
	return containersMetadata, nil
}

func containerInitPidAndRootfs(scanRoot string, runtimeName string, namespace string, id string, maxStateJSONFileSize int64) (int, string) {
	// A typical Linux case.
	if runtimeName == "io.containerd.runc.v2" {
		return runcInitPidAndRootfs(scanRoot, runtimeName, namespace, id, maxStateJSONFileSize)
	}

	// A typical Windows case.
	if runtimeName == "io.containerd.runhcs.v1" {
		return runhcsInitPid(scanRoot, runtimeName, namespace, id), ""
	}

	return -1, ""
}

func runcInitPidAndRootfs(scanRoot string, runtimeName string, namespace string, id string, maxStateJSONFileSize int64) (int, string) {
	// If a container is running by runc, the init pid is stored in the runc state.json file.
	// state.json file is located at the
	// <scanRoot>/<runcStateFilePrefix>/<namespace_name>/<container_id>/state.json path.
	statePath := filepath.Join(scanRoot, runcStateFilePrefix, namespace, id, "state.json")
	// Collect the fileinfo for the state.json file.
	fileInfo, err := os.Stat(statePath)
	if err != nil {
		log.Info("File state.json does not exists for container %v, error: %v", id, err)
		return -1, ""
	}
	if fileInfo.Size() > maxStateJSONFileSize {
		log.Errorf("Containerd Json state file %s is too large: %d", statePath, fileInfo.Size())
		return -1, ""
	}
	if _, err := os.Stat(statePath); err != nil {
		log.Info("File state.json does not exists for container %v, error: %v", id, err)
		return -1, ""
	}

	stateContent, err := os.ReadFile(statePath)
	if err != nil {
		log.Errorf("Could not read for %s state.json for container: %v, error: %v", id, err)
		return -1, ""
	}
	var runcState map[string]*json.RawMessage
	if err := json.Unmarshal([]byte(stateContent), &runcState); err != nil {
		log.Errorf("Can't unmarshal state.json for container %v , error: %v", id, err)
		return -1, ""
	}
	runcInitPID := runcState["init_process_pid"]
	if runcInitPID == nil {
		log.Errorf("Can't find field init_process_pid filed in state.json for container %v", id)
		return -1, ""
	}

	var initPID int
	if err := json.Unmarshal(*runcInitPID, &initPID); err != nil {
		log.Errorf("Can't find field init_process_pid in state.json for container %v, error: %v", id, err)
		return -1, ""
	}

	// Below get the rootfs path from the state.json file.
	config := runcState["config"]
	if config == nil {
		log.Errorf("Can't find field config filed in state.json for container %v", id)
		return initPID, ""
	}
	var configFields map[string]*json.RawMessage
	if err := json.Unmarshal(*config, &configFields); err != nil {
		log.Errorf("Can't unmarshal field config in state.json for container %v, error: %v", id, err)
		return initPID, ""
	}
	var rootfs string
	// rootfs field is in config: state[config][rootfs]
	if rootfsField := configFields["rootfs"]; rootfsField != nil {
		if err := json.Unmarshal(*rootfsField, &rootfs); err != nil {
			log.Errorf("Can't unmarshal field rootfs in state.json for container %v, error: %v", id, err)
			return initPID, ""
		}
	}

	return initPID, rootfs
}

func runhcsInitPid(scanRoot string, runtimeName string, namespace string, id string) int {
	// If a container is running by runhcs, the init pid is stored in the runhcs shim.pid file.
	// shim.pid file is located at the
	// <scanRoot>/<runhcsStateFilePrefix>/<namespace_name>/<container_id>/shim.pid.
	shimPIDPath := filepath.Join(scanRoot, runhcsStateFilePrefix, namespace, id, "shim.pid")
	if _, err := os.Stat(shimPIDPath); err != nil {
		log.Info("File shim.pid does not exists for container %v, error: %v", id, err)
		return -1
	}

	shimPIDContent, err := os.ReadFile(shimPIDPath)
	if err != nil {
		log.Errorf("Could not read for %s shim.pid for container: %v, error: %v", id, err)
		return -1
	}
	shimPidStr := strings.TrimSpace(string(shimPIDContent))
	initPID, err := strconv.Atoi(shimPidStr)
	if err != nil {
		log.Errorf("Can't convert shim.pid content to int for container %v, error: %v", id, err)
		return -1
	}
	return initPID
}

// ToPURL converts an inventory created by this extractor into a PURL.
func (e Extractor) ToPURL(i *extractor.Inventory) (*purl.PackageURL, error) { return nil, nil }

// ToCPEs is not applicable as this extractor does not infer CPEs from the Inventory.
func (e Extractor) ToCPEs(i *extractor.Inventory) ([]string, error) { return []string{}, nil }

// Ecosystem returns a synthetic ecosystem since the Inventory is not a software package.
func (Extractor) Ecosystem(i *extractor.Inventory) (string, error) { return "containerd", nil }
