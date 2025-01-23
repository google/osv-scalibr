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

// Package fakeclient contains a fake implementation of the containerd client for testing purposes.
package fakeclient

import (
	"context"
	"fmt"

	containerd "github.com/containerd/containerd"
	tasks "github.com/containerd/containerd/api/services/tasks/v1"
	task "github.com/containerd/containerd/api/types/task"
	"github.com/containerd/containerd/cio"
	"github.com/containerd/containerd/containers"
	"github.com/containerd/containerd/namespaces"
	"github.com/containerd/containerd/oci"
	plugin "github.com/google/osv-scalibr/extractor/standalone/containers/containerd"
	"github.com/opencontainers/go-digest"
	imagespecs "github.com/opencontainers/image-spec/specs-go/v1"
	runtimespecs "github.com/opencontainers/runtime-spec/specs-go"
	"google.golang.org/grpc"
)

// CtrdClient is a fake implementation of CtrdClient for testing purposes.
type CtrdClient struct {
	plugin.CtrdClient
	tasksService tasks.TasksClient
	nsService    namespaces.Store
	// A map of task IDs to containerd.Container objects.
	ctrTasksIDs map[string]containerd.Container
	// A map of namespace name to task IDs that are running in that namespace.
	nssTaskIDs map[string][]string
	// List of all active tasks that will be returned by the FakeTaskService.
	tsks []*task.Process
	// A map of container ID to containerd.Container object.
	ctrs []containerd.Container
}

// NewFakeCtrdClient creates a new fake containerd client.
func NewFakeCtrdClient(ctx context.Context, nssTaskIDs map[string][]string, tsks []*task.Process, ctrs []containerd.Container) (CtrdClient, error) {
	ctrTasks, err := initContainerTasks(tsks, ctrs)
	if err != nil {
		return CtrdClient{}, err
	}

	nss := make([]string, 0, len(nssTaskIDs))
	for ns := range nssTaskIDs {
		nss = append(nss, ns)
	}

	return CtrdClient{
		tasksService: NewFakeTasksService(tsks, nssTaskIDs),
		nsService:    NewFakeNamespacesService(nss),
		ctrTasksIDs:  ctrTasks,
		nssTaskIDs:   nssTaskIDs,
		ctrs:         ctrs,
		tsks:         tsks,
	}, nil
}

// LoadContainer returns the containerd.Container object for the given task ID from ctrTasksIDs.
func (c *CtrdClient) LoadContainer(ctx context.Context, id string) (containerd.Container, error) {
	if ctr, ok := c.ctrTasksIDs[id]; ok {
		return ctr, nil
	}
	return nil, fmt.Errorf("no container found with task id %v", id)
}

// NamespaceService returns the fake namespaces service for testing purposes.
func (c *CtrdClient) NamespaceService() namespaces.Store {
	return c.nsService
}

// TaskService returns the fake task service for testing purposes.
func (c *CtrdClient) TaskService() tasks.TasksClient {
	return c.tasksService
}

// Close is a no-op for the fake containerd client.
func (c *CtrdClient) Close() error {
	return nil
}

// initContainerTasks initializes the ctrTasksIDs map.
func initContainerTasks(tsks []*task.Process, ctrs []containerd.Container) (map[string]containerd.Container, error) {
	ctrTasksIDs := make(map[string]containerd.Container)

	for _, ctr := range ctrs {
		for _, task := range tsks {
			if task.ID == ctr.ID() {
				ctrTasksIDs[ctr.ID()] = ctr
				break
			}
		}
		// All containers are expected to have a task.
		if ctrTasksIDs[ctr.ID()] == nil {
			return nil, fmt.Errorf("no task found for container %v", ctr.ID())
		}
	}
	return ctrTasksIDs, nil
}

// TasksService is a fake implementation of the containerd tasks service.
type TasksService struct {
	tasks.TasksClient
	tasks      []*task.Process
	nssTaskIDs map[string][]string
}

// NewFakeTasksService creates a new fake tasks service.
func NewFakeTasksService(tasks []*task.Process, nssTaskIDs map[string][]string) *TasksService {
	return &TasksService{
		tasks:      tasks,
		nssTaskIDs: nssTaskIDs,
	}
}

// List returns a list of tasks for a namespace that is obtained from the context.
func (s *TasksService) List(ctx context.Context, in *tasks.ListTasksRequest, opts ...grpc.CallOption) (*tasks.ListTasksResponse, error) {
	var tsks []*task.Process

	ns, ok := namespaces.Namespace(ctx)
	if !ok {
		return &tasks.ListTasksResponse{Tasks: []*task.Process{}}, fmt.Errorf("no namespace found in context")
	}

	ids := s.nssTaskIDs[ns]
	if ids == nil {
		return &tasks.ListTasksResponse{Tasks: []*task.Process{}}, nil
	}

	for _, id := range ids {
		for _, t := range s.tasks {
			if id == t.ID {
				tsks = append(tsks, t)
				break
			}
		}
	}

	return &tasks.ListTasksResponse{Tasks: tsks}, nil
}

// NamespacesService is a fake implementation of the containerd namespaces service.
type NamespacesService struct {
	namespaces.Store
	namespaces []string
}

// NewFakeNamespacesService creates a new fake namespaces service.
func NewFakeNamespacesService(namespaces []string) *NamespacesService {
	return &NamespacesService{
		namespaces: namespaces,
	}
}

// List returns a list of all namespaces that are stored in the fake namespaces service.
func (s *NamespacesService) List(ctx context.Context) ([]string, error) {
	return s.namespaces, nil
}

// Container is a fake implementation of the containerd container object.
type Container struct {
	containerd.Container
	id     string
	image  string
	digest string
	rootfs string
}

// NewFakeContainer creates a new fake instance of containerd container.
func NewFakeContainer(id, image, digest, rootfs string) *Container {
	return &Container{
		id:     id,
		image:  image,
		digest: digest,
		rootfs: rootfs,
	}
}

// ID returns the container's unique id.
func (c *Container) ID() string {
	return c.id
}

// Info returns the underlying container record type.
func (c *Container) Info(ctx context.Context, opts ...containerd.InfoOpts) (containers.Container, error) {
	return containers.Container{
		ID:    c.id,
		Image: c.image,
		Labels: map[string]string{
			"image": c.image,
		},
		Runtime: containers.RuntimeInfo{Name: "fake_runc"},
	}, nil
}

func (c *Container) Task(context.Context, cio.Attach) (containerd.Task, error) {
	return NewFakeTask(c.rootfs), nil
}

// Image returns the underlying container Image object with a given digest.
func (c *Container) Image(ctx context.Context) (containerd.Image, error) {
	return NewFakeImage(c.digest), nil
}

// Image is a fake implementation of the containerd image object.
type Image struct {
	containerd.Image
	digest string
}

// NewFakeImage creates a new fake instance of containerd image.
func NewFakeImage(digest string) *Image {
	return &Image{
		digest: digest,
	}
}

// Target returns the image's target descriptor with the image's digest only.
func (i *Image) Target() imagespecs.Descriptor {
	return imagespecs.Descriptor{
		Digest:    digest.Digest(i.digest),
		MediaType: "fake_media_type",
	}
}

// Task is a fake implementation of the containerd task object.
type Task struct {
	containerd.Task
	rootfs string
}

// NewFakeTask creates a new fake instance of containerd image.
func NewFakeTask(rootfs string) *Task {
	return &Task{
		rootfs: rootfs,
	}
}

// Spec returns the task runtime spec with the rootfs path only.
func (t *Task) Spec(ctx context.Context) (*oci.Spec, error) {
	return &oci.Spec{Root: &runtimespecs.Root{Path: t.rootfs}}, nil
}
