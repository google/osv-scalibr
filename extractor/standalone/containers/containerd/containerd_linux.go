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

//go:build linux

// Package containerd extracts container inventory from containerd API.
package containerd

import (
	"context"
	"errors"
	"os"
	"path/filepath"

	containerd "github.com/containerd/containerd"
	tasks "github.com/containerd/containerd/api/services/tasks/v1"
	task "github.com/containerd/containerd/api/types/task"
	"github.com/containerd/containerd/namespaces"
	"github.com/google/osv-scalibr/extractor"
	"github.com/google/osv-scalibr/extractor/standalone"
	"github.com/google/osv-scalibr/extractor/standalone/containers/containerd/containerdmetadata"
	"github.com/google/osv-scalibr/inventory"
	"github.com/google/osv-scalibr/log"
	"github.com/google/osv-scalibr/plugin"
)

const (
	// Name is the unique name of this extractor.
	Name = "containers/containerd-runtime"

	// defaultContainerdSocketAddr is the default path to the containerd socket.
	defaultContainerdSocketAddr = "/run/containerd/containerd.sock"

	// defaultContainerdRootfsPrefix is the default path to the containerd tasks rootfs.
	// It is used if containerd API does not return the rootfs path in the container spec.
	defaultContainerdRootfsPrefix = "/run/containerd/io.containerd.runtime.v2.task/"
)

// CtrdClient is an interface that provides an abstraction on top of the containerd client.
// Needed for testing purposes.
type CtrdClient interface {
	LoadContainer(ctx context.Context, id string) (containerd.Container, error)
	NamespaceService() namespaces.Store
	TaskService() tasks.TasksClient
	Close() error
}

// Config is the configuration for the Extractor.
type Config struct {
	// ContainerdSocketAddr is the local path to the containerd socket.
	// Used further to crete a client for containerd API.
	ContainerdSocketAddr string
}

// DefaultConfig returns the default configuration for the containerd extractor.
func DefaultConfig() Config {
	return Config{
		ContainerdSocketAddr: defaultContainerdSocketAddr,
	}
}

// Extractor implements the containerd runtime extractor.
type Extractor struct {
	client              CtrdClient
	socketAddr          string
	checkIfSocketExists bool
	initNewCtrdClient   bool
}

// New creates a new containerd client and returns a containerd container inventory extractor.
func New(cfg Config) standalone.Extractor {
	return &Extractor{
		client:              nil,
		socketAddr:          cfg.ContainerdSocketAddr,
		checkIfSocketExists: true,
		initNewCtrdClient:   true,
	}
}

// NewDefault returns an extractor with the default config settings.
func NewDefault() standalone.Extractor {
	return New(DefaultConfig())
}

// NewWithClient creates a new extractor with the provided containerd client.
// Needed for testing purposes.
func NewWithClient(cli CtrdClient, socketAddr string) *Extractor {
	// Uses the provided containerd client and just returns the extractor.
	return &Extractor{
		client:              cli,
		socketAddr:          socketAddr,
		checkIfSocketExists: false, // Not needed if client already provided.
		initNewCtrdClient:   false, // Not needed if client already provided.
	}
}

// Config returns the configuration of the extractor.
func (e Extractor) Config() Config {
	return Config{
		ContainerdSocketAddr: e.socketAddr,
	}
}

// Name of the extractor.
func (e Extractor) Name() string { return Name }

// Version of the extractor.
func (e Extractor) Version() int { return 0 }

// Requirements of the extractor.
func (e Extractor) Requirements() *plugin.Capabilities {
	return &plugin.Capabilities{
		OS:            plugin.OSLinux,
		RunningSystem: true,
	}
}

// Extract extracts containers from the containerd API.
func (e *Extractor) Extract(ctx context.Context, input *standalone.ScanInput) (inventory.Inventory, error) {
	var result = []*extractor.Package{}
	if e.checkIfSocketExists {
		if _, err := os.Stat(e.socketAddr); err != nil {
			log.Infof("Containerd socket %v does not exist, skipping extraction.", e.socketAddr)
			return inventory.Inventory{}, err
		}
	}
	// Creating client here instead of New() to prevent client creation when extractor is not in use.
	if e.initNewCtrdClient {
		// Create a new containerd API client using the provided socket address
		// and reset it in the extractor.
		cli, err := containerd.New(e.socketAddr)
		if err != nil {
			log.Errorf("Failed to connect to containerd socket %v, error: %v", e.socketAddr, err)
			return inventory.Inventory{}, err
		}
		e.client = cli
		e.initNewCtrdClient = false
	}

	if e.client == nil {
		return inventory.Inventory{}, errors.New("containerd API client is not initialized")
	}

	ctrMetadata, err := containersFromAPI(ctx, e.client)
	if err != nil {
		log.Errorf("Could not get container package from the containerd: %v", err)
		return inventory.Inventory{}, err
	}

	for _, ctr := range ctrMetadata {
		pkg := &extractor.Package{
			Name:      ctr.ImageName,
			Version:   ctr.ImageDigest,
			Locations: []string{ctr.RootFS},
			Metadata:  &ctr,
		}
		result = append(result, pkg)
	}

	defer e.client.Close()
	return inventory.Inventory{Packages: result}, nil
}

func containersFromAPI(ctx context.Context, client CtrdClient) ([]containerdmetadata.Metadata, error) {
	var metadata []containerdmetadata.Metadata

	// Get list of namespaces from the containerd API.
	nss, err := namespacesFromAPI(ctx, client)
	if err != nil {
		log.Errorf("Could not get a list of namespaces from the containerd: %v", err)
		return nil, err
	}

	for _, ns := range nss {
		// For each namespace returned by the API, get the containers metadata.
		ctx := namespaces.WithNamespace(ctx, ns)
		ctrs := containersMetadata(ctx, client, ns, defaultContainerdRootfsPrefix)
		// Merge all containers metadata items for all namespaces into a single list.
		metadata = append(metadata, ctrs...)
	}
	return metadata, nil
}

func namespacesFromAPI(ctx context.Context, client CtrdClient) ([]string, error) {
	nsService := client.NamespaceService()
	nss, err := nsService.List(ctx)
	if err != nil {
		return nil, err
	}

	return nss, nil
}

func containersMetadata(ctx context.Context, client CtrdClient, namespace string, defaultAbsoluteToBundlePath string) []containerdmetadata.Metadata {
	var containersMetadata []containerdmetadata.Metadata

	taskService := client.TaskService()
	// List all running tasks, only running tasks have a container associated with them.
	listTasksReq := &tasks.ListTasksRequest{Filter: "status=running"}
	listTasksResp, err := taskService.List(ctx, listTasksReq)
	if err != nil {
		log.Errorf("Failed to list tasks: %v", err)
	}

	// For each running task, get the container information associated with it.
	for _, task := range listTasksResp.Tasks {
		md, err := taskMetadata(ctx, client, task, namespace, defaultAbsoluteToBundlePath)
		if err != nil {
			log.Errorf("Failed to get task metadata for task %v: %v", task.ID, err)
			continue
		}

		containersMetadata = append(containersMetadata, md)
	}
	return containersMetadata
}

func taskMetadata(ctx context.Context, client CtrdClient, task *task.Process, namespace string, defaultAbsoluteToBundlePath string) (containerdmetadata.Metadata, error) {
	var md containerdmetadata.Metadata

	container, err := client.LoadContainer(ctx, task.ID)
	if err != nil {
		log.Errorf("Failed to load container for task %v, error: %v", task.ID, err)
		return md, err
	}

	info, err := container.Info(ctx)
	if err != nil {
		log.Errorf("Failed to obtain container info for container %v, error: %v", task.ID, err)
		return md, err
	}

	image, err := container.Image(ctx)
	if err != nil {
		log.Errorf("Failed to obtain container image for container %v, error: %v", task.ID, err)
		return md, err
	}

	ctdTask, err := container.Task(ctx, nil)
	if err != nil {
		log.Errorf("Failed to obtain containerd container task data for container %v, error: %v", task.ID, err)
		return md, err
	}

	spec, err := ctdTask.Spec(ctx)
	if err != nil {
		log.Errorf("Failed to obtain containerd container task spec for container %v, error: %v", task.ID, err)
		return md, err
	}
	// Defined in https://github.com/opencontainers/runtime-spec/blob/main/config.md#root. For POSIX
	// platforms, path is either an absolute path or a relative path to the bundle. examples as below:
	// "/run/containerd/io.containerd.runtime.v2.task/default/nginx-test/rootfs" or "rootfs".
	rootfs := ""
	switch {
	case filepath.IsAbs(spec.Root.Path):
		rootfs = spec.Root.Path
	case spec.Root.Path != "":
		log.Infof("Rootfs is a relative path for a container: %v, concatenating rootfs path prefix", task.ID)
		rootfs = filepath.Join(defaultAbsoluteToBundlePath, namespace, task.ID, spec.Root.Path)
	case spec.Root.Path == "":
		log.Infof("Rootfs is empty for a container: %v, using default rootfs path prefix", task.ID)
		rootfs = filepath.Join(defaultAbsoluteToBundlePath, namespace, task.ID, "rootfs")
	}

	name := info.Image
	runtime := info.Runtime.Name
	digest := image.Target().Digest.String()
	pid := int(task.Pid)

	md = containerdmetadata.Metadata{
		Namespace:   namespace,
		ImageName:   name,
		ImageDigest: digest,
		Runtime:     runtime,
		ID:          task.ID,
		PID:         pid,
		RootFS:      rootfs,
	}

	return md, nil
}
