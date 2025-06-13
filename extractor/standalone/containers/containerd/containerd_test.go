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

// Package containerd_test contains unit tests for containerd extractor.
package containerd_test

import (
	"context"
	"fmt"
	"runtime"
	"slices"
	"testing"

	"github.com/containerd/containerd/api/types/task"
	containerd "github.com/containerd/containerd/v2/client"
	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/google/osv-scalibr/extractor"
	"github.com/google/osv-scalibr/extractor/standalone"
	plugin "github.com/google/osv-scalibr/extractor/standalone/containers/containerd"
	md "github.com/google/osv-scalibr/extractor/standalone/containers/containerd/containerdmetadata"
	"github.com/google/osv-scalibr/extractor/standalone/containers/containerd/fakeclient"
	"github.com/google/osv-scalibr/inventory"
)

func TestExtract(t *testing.T) {
	tests := []struct {
		name         string
		onGoos       []string
		nssTaskIDs   map[string][]string
		tsks         []*task.Process
		ctrs         []containerd.Container
		wantPackages []*extractor.Package
		wantErr      error
	}{
		{
			name:         "valid with no tasks",
			onGoos:       []string{"linux"},
			nssTaskIDs:   map[string][]string{"default": {}, "k8s.io": {}},
			tsks:         []*task.Process{},
			ctrs:         []containerd.Container{},
			wantPackages: []*extractor.Package{},
		},
		{
			name:       "valid with tasks and rootfs",
			onGoos:     []string{"linux"},
			nssTaskIDs: map[string][]string{"default": {"123456789"}, "k8s.io": {"567890123"}},
			tsks:       []*task.Process{{ID: "123456789", ContainerID: "", Pid: 12345}, {ID: "567890123", ContainerID: "", Pid: 5678}},
			ctrs:       []containerd.Container{fakeclient.NewFakeContainer("123456789", "image1", "digest1", "/run/containerd/io.containerd.runtime.v2.task/default/123456789/rootfs"), fakeclient.NewFakeContainer("567890123", "image2", "digest2", "/run/containerd/io.containerd.runtime.v2.task/k8s.io/567890123/rootfs")},
			wantPackages: []*extractor.Package{
				{
					Name:      "image1",
					Version:   "digest1",
					Locations: []string{"/run/containerd/io.containerd.runtime.v2.task/default/123456789/rootfs"},
					Metadata: &md.Metadata{
						Namespace:   "default",
						ImageName:   "image1",
						ImageDigest: "digest1",
						Runtime:     "fake_runc",
						ID:          "123456789",
						PID:         12345,
						RootFS:      "/run/containerd/io.containerd.runtime.v2.task/default/123456789/rootfs",
					},
				},
				{
					Name:      "image2",
					Version:   "digest2",
					Locations: []string{"/run/containerd/io.containerd.runtime.v2.task/k8s.io/567890123/rootfs"},
					Metadata: &md.Metadata{
						Namespace:   "k8s.io",
						ImageName:   "image2",
						ImageDigest: "digest2",
						ID:          "567890123",
						Runtime:     "fake_runc",
						PID:         5678,
						RootFS:      "/run/containerd/io.containerd.runtime.v2.task/k8s.io/567890123/rootfs",
					},
				},
			},
		},
		{
			name:       "valid with tasks and no rootfs",
			onGoos:     []string{"linux"},
			nssTaskIDs: map[string][]string{"default": {"123456789"}, "k8s.io": {"567890123"}},
			tsks:       []*task.Process{{ID: "123456789", ContainerID: "", Pid: 12345}, {ID: "567890123", ContainerID: "", Pid: 5678}},
			ctrs:       []containerd.Container{fakeclient.NewFakeContainer("123456789", "image1", "digest1", ""), fakeclient.NewFakeContainer("567890123", "image2", "digest2", "")},
			wantPackages: []*extractor.Package{
				{
					Name:      "image1",
					Version:   "digest1",
					Locations: []string{"/run/containerd/io.containerd.runtime.v2.task/default/123456789/rootfs"},
					Metadata: &md.Metadata{
						Namespace:   "default",
						ImageName:   "image1",
						ImageDigest: "digest1",
						Runtime:     "fake_runc",
						ID:          "123456789",
						PID:         12345,
						RootFS:      "/run/containerd/io.containerd.runtime.v2.task/default/123456789/rootfs",
					},
				},
				{
					Name:      "image2",
					Version:   "digest2",
					Locations: []string{"/run/containerd/io.containerd.runtime.v2.task/k8s.io/567890123/rootfs"},
					Metadata: &md.Metadata{
						Namespace:   "k8s.io",
						ImageName:   "image2",
						ImageDigest: "digest2",
						ID:          "567890123",
						Runtime:     "fake_runc",
						PID:         5678,
						RootFS:      "/run/containerd/io.containerd.runtime.v2.task/k8s.io/567890123/rootfs",
					},
				},
			},
		},
		{
			name:       "valid with tasks and relative-path-only rootfs",
			onGoos:     []string{"linux"},
			nssTaskIDs: map[string][]string{"default": {"123456788"}, "k8s.io": {"567890122"}},
			tsks:       []*task.Process{{ID: "123456788", ContainerID: "", Pid: 12346}, {ID: "567890122", ContainerID: "", Pid: 5677}},
			ctrs:       []containerd.Container{fakeclient.NewFakeContainer("123456788", "image1", "digest1", "test/rootfs"), fakeclient.NewFakeContainer("567890122", "image2", "digest2", "test2/rootfs")},
			wantPackages: []*extractor.Package{
				{
					Name:      "image1",
					Version:   "digest1",
					Locations: []string{"/run/containerd/io.containerd.runtime.v2.task/default/123456788/test/rootfs"},
					Metadata: &md.Metadata{
						Namespace:   "default",
						ImageName:   "image1",
						ImageDigest: "digest1",
						Runtime:     "fake_runc",
						ID:          "123456788",
						PID:         12346,
						RootFS:      "/run/containerd/io.containerd.runtime.v2.task/default/123456788/test/rootfs",
					},
				},
				{
					Name:      "image2",
					Version:   "digest2",
					Locations: []string{"/run/containerd/io.containerd.runtime.v2.task/k8s.io/567890122/test2/rootfs"},
					Metadata: &md.Metadata{
						Namespace:   "k8s.io",
						ImageName:   "image2",
						ImageDigest: "digest2",
						ID:          "567890122",
						Runtime:     "fake_runc",
						PID:         5677,
						RootFS:      "/run/containerd/io.containerd.runtime.v2.task/k8s.io/567890122/test2/rootfs",
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
			cli, err := fakeclient.NewFakeCtrdClient(context.Background(), tt.nssTaskIDs, tt.tsks, tt.ctrs)
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
			wantInv := inventory.Inventory{Packages: tt.wantPackages}
			if diff := cmp.Diff(wantInv, got, ignoreOrder); diff != "" {
				t.Errorf("Extract(%s) (-want +got):\n%s", tt.name, diff)
			}
		})
	}
}
