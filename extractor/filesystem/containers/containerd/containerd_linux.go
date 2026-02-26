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

// Package containerd extracts container package from containerd metadb database.
package containerd

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"time"

	"github.com/containerd/containerd/metadata"
	"github.com/containerd/containerd/namespaces"
	"github.com/google/osv-scalibr/extractor"
	"github.com/google/osv-scalibr/extractor/filesystem"
	"github.com/google/osv-scalibr/extractor/filesystem/internal/units"
	"github.com/google/osv-scalibr/inventory"
	"github.com/google/osv-scalibr/log"
	"github.com/google/osv-scalibr/plugin"
	bolt "go.etcd.io/bbolt"

	cpb "github.com/google/osv-scalibr/binary/proto/config_go_proto"
)

const (
	// Name is the unique name of this extractor.
	Name = "containers/containerd"

	// defaultMaxFileSize is the maximum file size.
	// If Extract gets a bigger file, it will return an error.
	defaultMaxFileSize = 500 * units.MiB

	// Prefix of the path for container's grpc container status file, used to collect pid for a container.
	criPluginStatusFilePrefix = "var/lib/containerd/io.containerd.grpc.v1.cri/containers/"

	// Prefix of the path for snapshotter overlayfs snapshots folders.
	overlayfsSnapshotsPath = "var/lib/containerd/io.containerd.snapshotter.v1.overlayfs/snapshots"
	// The path for the metadata.db file which will be used to parse the mapping between folders and container's mount points.
	snapshotterMetadataDBPath = "var/lib/containerd/io.containerd.snapshotter.v1.overlayfs/metadata.db"

	// Prefix of the path for snapshotter gcfs folders.
	gcfsSnapshotsPath = "var/lib/containerd/io.containerd.snapshotter.v1.gcfs/snapshotter/snapshots"
	gcfsLayersPath    = "var/lib/containerd/io.containerd.snapshotter.v1.gcfs/snapshotter/layers"
	// The path for the metadata.db file for gcfs.
	gcfsMetadataDBPath = "var/lib/containerd/io.containerd.snapshotter.v1.gcfs/snapshotter/metadata.db"

	// Content store blobs path.
	contentBlobsPath = "var/lib/containerd/io.containerd.content.v1.content/blobs/sha256"

	// The path for the meta.db file which will be used to parse container metadata on Linux systems.
	linuxMetaDBPath = "var/lib/containerd/io.containerd.metadata.v1.bolt/meta.db"
	// Prefix of the path for runhcs state files, used to check if a container is running by runhcs.
	runhcsStateFilePrefix = "ProgramData/containerd/state/io.containerd.runtime.v2.task/"
)

// Extractor extracts containers from the containerd metadb file.
type Extractor struct {
	maxMetaDBFileSize int64
}

// New returns a containerd container package extractor.
func New(cfg *cpb.PluginConfig) (filesystem.Extractor, error) {
	maxFileSize := defaultMaxFileSize
	if cfg.GetMaxFileSizeBytes() > 0 {
		maxFileSize = cfg.GetMaxFileSizeBytes()
	}

	specific := plugin.FindConfig(cfg, func(c *cpb.PluginSpecificConfig) *cpb.ContainerdConfig { return c.GetContainerd() })
	if specific.GetMaxFileSizeBytes() > 0 {
		maxFileSize = specific.GetMaxFileSizeBytes()
	}

	return &Extractor{maxMetaDBFileSize: maxFileSize}, nil
}

// Name of the extractor.
func (e Extractor) Name() string { return Name }

// Version of the extractor.
func (e Extractor) Version() int { return 0 }

// Requirements of the extractor.
func (e Extractor) Requirements() *plugin.Capabilities { return &plugin.Capabilities{DirectFS: true} }

// FileRequired returns true if the specified file matches containerd metaDB file pattern.
func (e Extractor) FileRequired(api filesystem.FileAPI) bool {
	path := api.Path()
	// On Windows the metadb file is expected to be located at the
	// <scanRoot>/ProgramData/containerd/root/io.containerd.metadata.v1.bolt/meta.db path.
	switch runtime.GOOS {
	case "windows":
		return path == "ProgramData/containerd/root/io.containerd.metadata.v1.bolt/meta.db"

	// On Linux the metadb file is expected to be located at the
	// <scanRoot>/var/lib/containerd/io.containerd.metadata.v1.bolt/meta.db path.
	default:
		return path == linuxMetaDBPath
	}
}

// Extract container package through the containerd metadb file passed as the scan input.
func (e Extractor) Extract(ctx context.Context, input *filesystem.ScanInput) (inventory.Inventory, error) {
	pkgs := []*extractor.Package{}

	if input.Info != nil && input.Info.Size() > e.maxMetaDBFileSize {
		return inventory.Inventory{}, fmt.Errorf("containerd metadb file is too large: %d", input.Info.Size())
	}
	// Timeout is added to make sure Scalibr does not hand if the metadb file is open by another process.
	// This will still allow to handle the snapshot of a machine.
	metaDB, err := bolt.Open(filepath.Join(input.Root, input.Path), 0444, &bolt.Options{Timeout: 1 * time.Second})
	if err != nil {
		return inventory.Inventory{}, fmt.Errorf("could not read the containerd metadb file: %w", err)
	}

	defer metaDB.Close()

	ctrMetadata, err := containersFromMetaDB(ctx, metaDB, input.Root, e.maxMetaDBFileSize, input.Path)
	if err != nil {
		log.Errorf("Could not get container package from the containerd metadb file: %v", err)
		return inventory.Inventory{}, err
	}

	for _, ctr := range ctrMetadata {
		pkg := &extractor.Package{
			Name:      ctr.ImageName,
			Version:   ctr.ImageDigest,
			Locations: []string{input.Path},
			Metadata:  &ctr,
		}
		pkgs = append(pkgs, pkg)
	}
	return inventory.Inventory{Packages: pkgs}, nil
}

// This method checks if the given file is valid to be opened, and make sure it's not oversized.
func fileSizeCheck(filepath string, maxFileSize int64) (err error) {
	fileInfo, err := os.Stat(filepath)
	if err != nil {
		return err
	}
	if fileInfo.Size() > maxFileSize {
		return fmt.Errorf("file %s is too large: %d", filepath, fileInfo.Size())
	}
	return nil
}

// namespacesFromMetaDB returns the list of namespaces stored in the containerd metaDB file.
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

func containersFromMetaDB(ctx context.Context, metaDB *bolt.DB, scanRoot string, maxMetaDBFileSize int64, dbPath string) ([]Metadata, error) {
	var containersMetadata []Metadata
	snapshotMetadataCache := make(map[string][]SnapshotMetadata)

	if dbPath == linuxMetaDBPath {
		fullMetadataDBPath := filepath.Join(scanRoot, snapshotterMetadataDBPath)
		if _, statErr := os.Stat(fullMetadataDBPath); statErr == nil {
			parsedMetadata, err := snapshotsMetadataFromDB(fullMetadataDBPath, maxMetaDBFileSize, "overlayfs")
			if err != nil {
				log.Errorf("could not collect snapshots metadata from DB %s: %v", fullMetadataDBPath, err)
			}
			snapshotMetadataCache["overlayfs"] = parsedMetadata
		}

		fullGcfsMetadataDBPath := filepath.Join(scanRoot, gcfsMetadataDBPath)
		if _, statErr := os.Stat(fullGcfsMetadataDBPath); statErr == nil {
			parsedMetadata, err := snapshotsMetadataFromDB(fullGcfsMetadataDBPath, maxMetaDBFileSize, "gcfs")
			if err != nil {
				log.Errorf("could not collect snapshots metadata from DB %s: %v", fullGcfsMetadataDBPath, err)
			}
			snapshotMetadataCache["gcfs"] = parsedMetadata
		}
	}

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
		ctx := namespaces.WithNamespace(ctx, ns)
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
			if initPID = containerInitPid(scanRoot, ctr.Runtime.Name, ns, id); initPID == -1 {
				continue
			}
			img, err := imageStore.Get(ctx, ctr.Image)
			if err != nil {
				log.Errorf("Could not find the image for container %v, error: %v", id, err)
			}

			var lowerDir, upperDir, workDir string

			// If the filesystem is overlayfs, then parse overlayfs metadata.db
			if ctr.Snapshotter == "overlayfs" {
				lowerDir, upperDir, workDir = collectOverlayFSDirs(scanRoot, snapshotMetadataCache[ctr.Snapshotter], ctr.SnapshotKey)
			} else if ctr.Snapshotter == "gcfs" {
				lowerDir, upperDir, workDir = collectGcfsDirs(scanRoot, snapshotMetadataCache[ctr.Snapshotter], ctr.SnapshotKey, img.Target.Digest.String(), id)
			}

			containersMetadata = append(containersMetadata,
				Metadata{Namespace: ns,
					ImageName:    img.Name,
					ImageDigest:  img.Target.Digest.String(),
					Runtime:      ctr.Runtime.Name,
					PodName:      ctr.Labels["io.kubernetes.pod.name"],
					PodNamespace: ctr.Labels["io.kubernetes.pod.namespace"],
					ID:           id,
					PID:          initPID,
					Snapshotter:  ctr.Snapshotter,
					SnapshotKey:  ctr.SnapshotKey,
					LowerDir:     lowerDir,
					UpperDir:     upperDir,
					WorkDir:      workDir})
		}
	}
	return containersMetadata, nil
}

// Trim the snapshot digest to match the snapshot key in the metadata.db file.
func digestSnapshotInfoMapping(snapshotsMetadata []SnapshotMetadata) map[string]SnapshotMetadata {
	digestSnapshotInfoMapping := make(map[string]SnapshotMetadata)
	for _, snapshotMetadata := range snapshotsMetadata {
		// The snapshotMetadata.Digest is in the format of ".*/<digest>".
		// The snapshotKey in the metadata.db file is the "<digest>" part.
		// If the snapshotMetadata.Digest does not have the "/" or "/" is the last character, then it's
		// not a valid snapshot digest.
		digestSplitterIndex := strings.LastIndex(snapshotMetadata.Digest, "/")
		if digestSplitterIndex == -1 || digestSplitterIndex == len(snapshotMetadata.Digest)-1 {
			continue
		}
		shorterDigest := snapshotMetadata.Digest[digestSplitterIndex+1:]
		digestSnapshotInfoMapping[shorterDigest] = snapshotMetadata
	}
	return digestSnapshotInfoMapping
}

// Format the lowerDir, upperDir and workDir for the container.
func collectOverlayFSDirs(scanRoot string, snapshotsMetadata []SnapshotMetadata, snapshotKey string) (string, string, string) {
	var lowerDirs []string
	var parentSnapshotIDs []uint64
	parentSnapshotIDs = getParentSnapshotIDByDigest(snapshotsMetadata, snapshotKey, parentSnapshotIDs)
	for _, parentSnapshotID := range parentSnapshotIDs {
		lowerDirs = append(lowerDirs, filepath.Join(scanRoot, overlayfsSnapshotsPath, strconv.FormatUint(parentSnapshotID, 10), "fs"))
	}
	// Sample lowerDir: lowerdir=/var/lib/containerd/io.containerd.snapshotter.v1.overlayfs/snapshots/15/fs:/var/lib/containerd/io.containerd.snapshotter.v1.overlayfs/snapshots/12/fs:/var/lib/containerd/io.containerd.snapshotter.v1.overlayfs/snapshots/8/fs:/var/lib/containerd/io.containerd.snapshotter.v1.overlayfs/snapshots/5/fs
	lowerDir := strings.Join(lowerDirs, ":")
	upperDir, workDir := getUpperAndWorkDirs(scanRoot, snapshotKey, overlayfsSnapshotsPath, snapshotsMetadata)
	return lowerDir, upperDir, workDir
}

// getImageDiffIDs extracts the layer DiffIDs from the image configuration blob in the content store.
//
// References:
//   - OCI Image Spec for Layer DiffID: https://github.com/opencontainers/image-spec/blob/v1.1.0/config.md#layer-diffid
//     The image configuration JSON specifies a `rootfs` object with a `diff_ids` array. A layer DiffID is the
//     digest over the layer's uncompressed tar archive.
//   - Containerd Content Store: Containerd downloads and retains the raw manifest and configuration blobs in its
//     content store (`var/lib/containerd/io.containerd.content.v1.content/blobs/sha256/`) locally on the GKE node.
//   - GCFS (Image Streaming): The GKE image streaming daemon (gcfs) mounts read-only layer contents directly via
//     their uncompressed DiffID strings in `/var/lib/containerd/io.containerd.snapshotter.v1.gcfs/snapshotter/layers/sha256=<Layer-DiffID>`.
func getImageDiffIDs(scanRoot string, manifestDigest string) ([]string, error) {
	manifestHash := strings.TrimPrefix(manifestDigest, "sha256:")
	manifestPath := filepath.Join(scanRoot, contentBlobsPath, manifestHash)

	manifestBytes, err := os.ReadFile(manifestPath)
	if err != nil {
		return nil, fmt.Errorf("could not read manifest blob: %w", err)
	}

	// First try to parse as an Index/ManifestList
	var index struct {
		Manifests []struct {
			Digest   string `json:"digest"`
			Platform struct {
				Architecture string `json:"architecture"`
				OS           string `json:"os"`
			} `json:"platform"`
		} `json:"manifests"`
	}
	// Try parsing as manifest directly
	var manifest struct {
		Config struct {
			Digest string `json:"digest"`
		} `json:"config"`
	}

	errIndex := json.Unmarshal(manifestBytes, &index)
	errManifest := json.Unmarshal(manifestBytes, &manifest)

	if errIndex != nil && errManifest != nil {
		return nil, fmt.Errorf("could not parse blob as either index or manifest: %w, %w", errIndex, errManifest)
	}

	// If there is no config digest, it might be an index
	if manifest.Config.Digest == "" && len(index.Manifests) > 0 {
		var selectedManifestDigest string
		// Default to amd64 linux
		// Note: GKE nodes mostly use linux/amd64, but can support Windows.
		// Currently, only linux/amd64 is actively supported for extracting DiffIDs from manifest lists.
		for _, m := range index.Manifests {
			if m.Platform.OS == "linux" && m.Platform.Architecture == "amd64" {
				selectedManifestDigest = m.Digest
				break
			}
		}
		// Fallback to the first one if amd64 linux is not found
		if selectedManifestDigest == "" {
			selectedManifestDigest = index.Manifests[0].Digest
		}

		// Read the actual manifest
		manifestHash = strings.TrimPrefix(selectedManifestDigest, "sha256:")
		manifestPath = filepath.Join(scanRoot, contentBlobsPath, manifestHash)
		manifestBytes, err = os.ReadFile(manifestPath)
		if err != nil {
			return nil, fmt.Errorf("could not read inner manifest blob: %w", err)
		}
		if err := json.Unmarshal(manifestBytes, &manifest); err != nil {
			return nil, fmt.Errorf("could not parse inner manifest blob: %w", err)
		}
	}

	configHash := strings.TrimPrefix(manifest.Config.Digest, "sha256:")
	if configHash == "" {
		return nil, errors.New("empty config digest in manifest")
	}

	configPath := filepath.Join(scanRoot, contentBlobsPath, configHash)
	configBytes, err := os.ReadFile(configPath)
	if err != nil {
		return nil, fmt.Errorf("could not read config blob: %w", err)
	}

	var config struct {
		RootFS struct {
			DiffIDs []string `json:"diff_ids"`
		} `json:"rootfs"`
	}
	if err := json.Unmarshal(configBytes, &config); err != nil {
		return nil, fmt.Errorf("could not parse config blob: %w", err)
	}

	return config.RootFS.DiffIDs, nil
}

// collectGcfsDirs constructs the lower, upper, and work dirs for a gcfs container.
func collectGcfsDirs(scanRoot string, snapshotsMetadata []SnapshotMetadata, snapshotKey string, manifestDigest string, containerID string) (string, string, string) {
	if manifestDigest == "" {
		return "", "", ""
	}
	diffIDs, err := getImageDiffIDs(scanRoot, manifestDigest)
	if err != nil {
		log.Errorf("Failed to get DiffIDs for container %v: %v", containerID, err)
		return "", "", ""
	}

	var lowerDirs []string
	// diff_ids are ordered base layer to top layer.
	// For gcfs, lowerDirs points to the read-only unpacked layers.
	for i := len(diffIDs) - 1; i >= 0; i-- {
		diffIDHash := strings.TrimPrefix(diffIDs[i], "sha256:")
		lowerDirs = append(lowerDirs, filepath.Join(scanRoot, gcfsLayersPath, "sha256="+diffIDHash))
	}
	lowerDir := strings.Join(lowerDirs, ":")

	upperDir, workDir := getUpperAndWorkDirs(scanRoot, snapshotKey, gcfsSnapshotsPath, snapshotsMetadata)
	return lowerDir, upperDir, workDir
}

// getUpperAndWorkDirs finds the active snapshot ID for the container's snapshotKey to build upper/work dirs.
func getUpperAndWorkDirs(scanRoot string, snapshotKey string, snapshotsPath string, snapshotsMetadata []SnapshotMetadata) (string, string) {
	for _, snapshotMetadata := range snapshotsMetadata {
		if strings.Contains(snapshotMetadata.Digest, snapshotKey) {
			upperDir := filepath.Join(scanRoot, snapshotsPath, strconv.FormatUint(snapshotMetadata.ID, 10), "fs")
			workDir := filepath.Join(scanRoot, snapshotsPath, strconv.FormatUint(snapshotMetadata.ID, 10), "work")
			return upperDir, workDir
		}
	}
	return "", ""
}

// Collect the parent snapshot ids of the given snapshot.
func getParentSnapshotIDByDigest(snapshotsMetadata []SnapshotMetadata, digest string, parentIDList []uint64) []uint64 {
	snapshotMetadataDict := digestSnapshotInfoMapping(snapshotsMetadata)
	if _, ok := snapshotMetadataDict[digest]; !ok {
		log.Errorf("Could not find the parent snapshot info in the metadata.db file for digest: %v", digest)
		return parentIDList
	}
	parentSnapshotMetadata := snapshotMetadataDict[digest]
	if strings.Contains(digest, "sha256:") {
		// start from its parent snapshots.
		parentIDList = append(parentIDList, parentSnapshotMetadata.ID)
	}
	if parentSnapshotMetadata.Parent == "" {
		return parentIDList
	}
	shorterDigest := parentSnapshotMetadata.Parent[strings.LastIndex(snapshotMetadataDict[digest].Parent, "/")+1:]
	return getParentSnapshotIDByDigest(snapshotsMetadata, shorterDigest, parentIDList)
}

// Parse the snapshots information from Metadata.db if db file is valid and not too large.
func snapshotsMetadataFromDB(fullMetadataDBPath string, maxMetaDBFileSize int64, fileSystemDriver string) ([]SnapshotMetadata, error) {
	// extracted snapshots metadata from the metadata.db file.
	var snapshotsMetadata []SnapshotMetadata

	// Check if the file is valid to be opened, and make sure it's not too large.
	err := fileSizeCheck(fullMetadataDBPath, maxMetaDBFileSize)
	if err != nil {
		return nil, fmt.Errorf("could not read the containerd metadb file: %w", err)
	}

	metadataDB, err := bolt.Open(fullMetadataDBPath, 0444, &bolt.Options{Timeout: 1 * time.Second})
	if err != nil {
		return nil, fmt.Errorf("could not read the containerd metadb file: %w", err)
	}
	defer metadataDB.Close()
	err = metadataDB.View(func(tx *bolt.Tx) error {
		snapshotsBucketByDigest, err := snapshotsBucketByDigest(tx)
		if err != nil {
			return fmt.Errorf("not able to grab the names of the snapshot buckets: %w", err)
		}
		// Store the important info of the snapshots into snapshotMetadata struct.
		snapshotsMetadata = snapshotMetadataFromSnapshotsBuckets(tx, snapshotsBucketByDigest, snapshotsMetadata, fileSystemDriver)
		return nil
	})
	if err != nil {
		log.Errorf("Not able to view the db: %v", err)
		return nil, err
	}
	return snapshotsMetadata, nil
}

// List the names of the snapshot buckets that are stored in the metadata.db file.
func snapshotsBucketByDigest(tx *bolt.Tx) ([]string, error) {
	// List of bucket names.These buckets stores snapshots information. Normally its name
	// is the digest.
	var snapshotsBucketByDigest []string
	//  metadata db structure: v1-> snapshots -> <snapshot_digest> -> <snapshot_info_fields>
	if tx == nil {
		return snapshotsBucketByDigest, errors.New("the transaction is nil")
	}
	if tx.Bucket([]byte("v1")) == nil {
		return snapshotsBucketByDigest, errors.New("could not find the v1 bucket in the metadata.db file")
	}
	if tx.Bucket([]byte("v1")).Bucket([]byte("snapshots")) == nil {
		return snapshotsBucketByDigest, errors.New("could not find the snapshots bucket in the metadata.db file")
	}
	snapshotsMetadataBucket := tx.Bucket([]byte("v1")).Bucket([]byte("snapshots"))
	err := snapshotsMetadataBucket.ForEach(func(k []byte, v []byte) error {
		// When the value is nil, it means it's a bucket. In this case, we would like to grab the
		// bucket name and visit it later.
		if v == nil {
			snapshotsBucketByDigest = append(snapshotsBucketByDigest, string(k))
		}
		return nil
	})
	return snapshotsBucketByDigest, err
}

func snapshotMetadataFromSnapshotsBuckets(tx *bolt.Tx, snapshotsBucketByDigest []string, snapshotsMetadata []SnapshotMetadata, fileSystemDriver string) []SnapshotMetadata {
	for _, shaDigest := range snapshotsBucketByDigest {
		if tx == nil {
			return snapshotsMetadata
		}
		if tx.Bucket([]byte("v1")) == nil {
			return snapshotsMetadata
		}
		if tx.Bucket([]byte("v1")).Bucket([]byte("snapshots")) == nil {
			return snapshotsMetadata
		}
		if tx.Bucket([]byte("v1")).Bucket([]byte("snapshots")).Bucket([]byte(shaDigest)) == nil {
			return snapshotsMetadata
		}
		// Get the bucket by digest.
		snapshotMetadataBucket := tx.Bucket([]byte("v1")).Bucket([]byte("snapshots")).Bucket([]byte(shaDigest))
		// This id is the corresponding folder name in overlayfs/snapshots folder.
		id := uint64(0)
		idByte := snapshotMetadataBucket.Get([]byte("id"))
		if idByte != nil {
			id, _ = binary.Uvarint(idByte)
		}
		// The status of the snapshot.
		kind := -1
		kindByte := snapshotMetadataBucket.Get([]byte("kind"))
		if kindByte != nil {
			kind = int(kindByte[0])
		}
		// The parent snapshot of the snapshot.
		parent := ""
		parentByte := snapshotMetadataBucket.Get([]byte("parent"))
		if parentByte != nil {
			parent = string(parentByte)
		}

		snapshotsMetadata = append(snapshotsMetadata, SnapshotMetadata{Digest: shaDigest, ID: id, Kind: kind, Parent: parent, FilesystemType: fileSystemDriver})
	}
	return snapshotsMetadata
}

func containerInitPid(scanRoot string, runtimeName string, namespace string, id string) int {
	// A typical Linux case.
	if runtimeName == "io.containerd.runc.v2" {
		return runcInitPid(scanRoot, id)
	}

	// A typical Windows case.
	if runtimeName == "io.containerd.runhcs.v1" {
		return runhcsInitPid(scanRoot, namespace, id)
	}

	return -1
}

func runcInitPid(scanRoot string, id string) int {
	// If a container is running by runc, the init pid is stored in the grpc status file.
	// status file is located at the
	// <scanRoot>/<criPluginStatusFilePrefix>/<container_id>/status path.
	statusPath := filepath.Join(scanRoot, criPluginStatusFilePrefix, id, "status")
	if _, err := os.Stat(statusPath); err != nil {
		log.Info("File status does not exists for container %v, error: %v", id, err)
		return -1
	}

	err := fileSizeCheck(statusPath, defaultMaxFileSize)
	if err != nil {
		return -1
	}

	initPID := -1

	statusContent, err := os.ReadFile(statusPath)
	if err != nil {
		log.Errorf("Could not read for %s status for container: %v", id, err)
		return -1
	}
	var grpcContainerStatus map[string]*json.RawMessage
	if err := json.Unmarshal(statusContent, &grpcContainerStatus); err != nil {
		log.Errorf("Can't unmarshal status for container %v , error: %v", id, err)
		return -1
	}

	if _, ok := grpcContainerStatus["Pid"]; !ok {
		log.Errorf("Can't find field pid filed in status for container %v", id)
		return -1
	}
	if err := json.Unmarshal(*grpcContainerStatus["Pid"], &initPID); err != nil {
		log.Errorf("Can't unmarshal pid in status for container %v, error: %v", id, err)
		return -1
	}

	return initPID
}

func runhcsInitPid(scanRoot string, namespace string, id string) int {
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
		log.Errorf("Could not read for %s shim.pid for container: %v", id, err)
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
