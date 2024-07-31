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

// Package containerd_test contains unit tests for containerd extractor.
package containerd_test

import (
	"context"
	"fmt"
	"runtime"
	"slices"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/containerd/containerd/api/types/task"
	containerd "github.com/containerd/containerd"
	"github.com/google/osv-scalibr/extractor"
	plugin "github.com/google/osv-scalibr/extractor/standalone/containers/containerd"
	"github.com/google/osv-scalibr/extractor/standalone/containers/containerd/fakeclient"
	"github.com/google/osv-scalibr/extractor/standalone"
)

func TestExtract(t *testing.T) {
	tests := []struct {
		name          string
		onGoos        []string
		nssTaskIds    map[string][]string
		tsks          []*task.Process
		ctrs          []containerd.Container
		wantInventory []*extractor.Inventory
		wantErr       error
	}{
		{
			name:          "valid with no tasks",
			onGoos:        []string{"linux"},
			nssTaskIds:    map[string][]string{"default": []string{}, "k8s.io": []string{}},
			tsks:          []*task.Process{},
			ctrs:          []containerd.Container{},
			wantInventory: []*extractor.Inventory{},
		},
		{
			name:       "valid with tasks and rootfs",
			onGoos:     []string{"linux"},
			nssTaskIds: map[string][]string{"default": []string{"123456789"}, "k8s.io": []string{"567890123"}},
			tsks:       []*task.Process{&task.Process{ID: "123456789", ContainerID: "", Pid: 12345}, &task.Process{ID: "567890123", ContainerID: "", Pid: 5678}},
			ctrs:       []containerd.Container{fakeclient.NewFakeContainer("123456789", "image1", "digest1", "/run/containerd/io.containerd.runtime.v2.task/default/123456789/rootfs"), fakeclient.NewFakeContainer("567890123", "image2", "digest2", "/run/containerd/io.containerd.runtime.v2.task/k8s.io/567890123/rootfs")},
			wantInventory: []*extractor.Inventory{
				&extractor.Inventory{
					Name:      "image1",
					Version:   "digest1",
					Locations: []string{"/run/containerd/io.containerd.runtime.v2.task/default/123456789/rootfs"},
					Metadata: &plugin.Metadata{
						Namespace:   "default",
						ImageName:   "image1",
						ImageDigest: "digest1",
						Runtime:     "fake_runc",
						ID:          "123456789",
						PID:         12345,
						Rootfs:      "/run/containerd/io.containerd.runtime.v2.task/default/123456789/rootfs",
					},
				},
				{
					Name:      "image2",
					Version:   "digest2",
					Locations: []string{"/run/containerd/io.containerd.runtime.v2.task/k8s.io/567890123/rootfs"},
					Metadata: &plugin.Metadata{
						Namespace:   "k8s.io",
						ImageName:   "image2",
						ImageDigest: "digest2",
						ID:          "567890123",
						Runtime:     "fake_runc",
						PID:         5678,
						Rootfs:      "/run/containerd/io.containerd.runtime.v2.task/k8s.io/567890123/rootfs",
					},
				},
			},
		},
		{
			name:       "valid with tasks and no rootfs",
			onGoos:     []string{"linux"},
			nssTaskIds: map[string][]string{"default": []string{"123456789"}, "k8s.io": []string{"567890123"}},
			tsks:       []*task.Process{&task.Process{ID: "123456789", ContainerID: "", Pid: 12345}, &task.Process{ID: "567890123", ContainerID: "", Pid: 5678}},
			ctrs:       []containerd.Container{fakeclient.NewFakeContainer("123456789", "image1", "digest1", ""), fakeclient.NewFakeContainer("567890123", "image2", "digest2", "")},
			wantInventory: []*extractor.Inventory{
				&extractor.Inventory{
					Name:      "image1",
					Version:   "digest1",
					Locations: []string{"/run/containerd/io.containerd.runtime.v2.task/default/123456789/rootfs"},
					Metadata: &plugin.Metadata{
						Namespace:   "default",
						ImageName:   "image1",
						ImageDigest: "digest1",
						Runtime:     "fake_runc",
						ID:          "123456789",
						PID:         12345,
						Rootfs:      "/run/containerd/io.containerd.runtime.v2.task/default/123456789/rootfs",
					},
				},
				{
					Name:      "image2",
					Version:   "digest2",
					Locations: []string{"/run/containerd/io.containerd.runtime.v2.task/k8s.io/567890123/rootfs"},
					Metadata: &plugin.Metadata{
						Namespace:   "k8s.io",
						ImageName:   "image2",
						ImageDigest: "digest2",
						ID:          "567890123",
						Runtime:     "fake_runc",
						PID:         5678,
						Rootfs:      "/run/containerd/io.containerd.runtime.v2.task/k8s.io/567890123/rootfs",
					},
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if len(tt.onGoos) > 0 && !slices.Contains(tt.onGoos, runtime.GOOS) {
				t.Skipf("Skipping test on %s", runtime.GOOS)
			}

			var input *standalone.ScanInput
			cli, err := fakeclient.NewFakeCtrdClient(context.Background(), tt.nssTaskIds, tt.tsks, tt.ctrs)
			if err != nil {
				t.Fatalf("NewFakeCtrdClient() error: %v", err)
			}
			e := plugin.NewWithClient(&cli, "test")
			got, err := e.Extract(context.Background(), input)
			if !cmp.Equal(err, tt.wantErr, cmpopts.EquateErrors()) {
				t.Fatalf("Extract(%+v) error: got %v, want %v\n", tt.name, err, tt.wantErr)
			}

			ignoreOrder := cmpopts.SortSlices(func(a, b any) bool {
				return fmt.Sprintf("%+v", a) < fmt.Sprintf("%+v", b)
			})
			if diff := cmp.Diff(tt.wantInventory, got, ignoreOrder); diff != "" {
				t.Errorf("Extract(%s) (-want +got):\n%s", tt.name, diff)
			}
		})
	}
}
