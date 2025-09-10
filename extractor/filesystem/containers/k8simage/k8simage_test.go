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

package k8simage_test

import (
	"context"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/google/osv-scalibr/extractor"
	"github.com/google/osv-scalibr/extractor/filesystem/containers/k8simage"
	"github.com/google/osv-scalibr/extractor/filesystem/simplefileapi"
	"github.com/google/osv-scalibr/inventory"
	"github.com/google/osv-scalibr/purl"
	"github.com/google/osv-scalibr/testing/extracttest"
)

func TestFileRequired(t *testing.T) {
	extr := k8simage.New(k8simage.DefaultConfig())

	tests := []struct {
		name string
		path string
		want bool
	}{
		{
			name: "K8s Deployment",
			path: "testdata/deployment.yaml",
			want: true,
		},
		{
			name: "K8s Deployment 2",
			path: "testdata/deployment2.yml",
			want: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			isRequired := extr.FileRequired(simplefileapi.New(tc.path, nil))
			if isRequired != tc.want {
				t.Fatalf("FileRequired(%s): got %v, want %v", tc.path, isRequired, tc.want)
			}
		})
	}
}

func TestExtract(t *testing.T) {
	tests := []struct {
		name         string
		path         string
		cfg          k8simage.Config
		wantPackages []*extractor.Package
	}{
		{
			name: "deployment with multiple containers",
			path: "testdata/deployment.yaml",
			cfg:  k8simage.DefaultConfig(),
			wantPackages: []*extractor.Package{
				{
					Name:      "alpine",
					Version:   "sha256:1ff6c18fbef2045af6b9c16bf034cc421a29027b800e4f9b68ae9b1cb3e9ae07",
					Locations: []string{"testdata/deployment.yaml"},
					PURLType:  purl.TypeK8sDocker,
				},
				{
					Name:      "postgres",
					Version:   "8",
					Locations: []string{"testdata/deployment.yaml"},
					PURLType:  purl.TypeK8sDocker,
				},
				{
					Name:      "nginx",
					Version:   "1.7.9",
					Locations: []string{"testdata/deployment.yaml"},
					PURLType:  purl.TypeK8sDocker,
				},
				{
					Name:      "my-demo-app",
					Version:   "latest",
					Locations: []string{"testdata/deployment.yaml"},
					PURLType:  purl.TypeK8sDocker,
				},
				{
					Name:      "alpine",
					Version:   "3.7",
					Locations: []string{"testdata/deployment.yaml"},
					PURLType:  purl.TypeK8sDocker,
				},
			},
		},
		{
			name: "pod with multiple documents",
			path: "testdata/pod.yaml",
			cfg:  k8simage.DefaultConfig(),
			wantPackages: []*extractor.Package{
				{
					Name:      "gcr.io/google-samples/hello-app",
					Version:   "2.0",
					Locations: []string{"testdata/pod.yaml"},
					PURLType:  purl.TypeK8sDocker,
				},
				{
					Name:      "gcr.io/google-samples/hello-app",
					Version:   "1.0",
					Locations: []string{"testdata/pod.yaml"},
					PURLType:  purl.TypeK8sDocker,
				},
			},
		},
		{
			name: "job with single container",
			path: "testdata/job.yaml",
			cfg:  k8simage.DefaultConfig(),
			wantPackages: []*extractor.Package{
				{
					Name:      "perl",
					Version:   "5.34.0",
					Locations: []string{"testdata/job.yaml"},
					PURLType:  purl.TypeK8sDocker,
				},
			},
		},
		{
			name: "replicaset with single container",
			path: "testdata/frontend.yaml",
			cfg:  k8simage.DefaultConfig(),
			wantPackages: []*extractor.Package{
				{
					Name:      "us-docker.pkg.dev/google-samples/containers/gke/gb-frontend",
					Version:   "v5",
					Locations: []string{"testdata/frontend.yaml"},
					PURLType:  purl.TypeK8sDocker,
				},
			},
		},
		{
			name: "multi-document with StatefulSet and Service",
			path: "testdata/service.yaml",
			cfg:  k8simage.DefaultConfig(),
			wantPackages: []*extractor.Package{
				{
					Name:      "registry.k8s.io/kubernetes-zookeeper",
					Version:   "1.0-3.4.10",
					Locations: []string{"testdata/service.yaml"},
					PURLType:  purl.TypeK8sDocker,
				},
			},
		},
		{
			name: "StatefulSet with single container",
			path: "testdata/StatefulSet.yaml",
			cfg:  k8simage.DefaultConfig(),
			wantPackages: []*extractor.Package{
				{
					Name:      "gcr.io/google-samples/cassandra",
					Version:   "v13",
					Locations: []string{"testdata/StatefulSet.yaml"},
					PURLType:  purl.TypeK8sDocker,
				},
			},
		},
		{
			name: "multi-document with Service and StatefulSet",
			path: "testdata/web.yaml",
			cfg:  k8simage.DefaultConfig(),
			wantPackages: []*extractor.Package{
				{
					Name:      "registry.k8s.io/nginx-slim",
					Version:   "0.21",
					Locations: []string{"testdata/web.yaml"},
					PURLType:  purl.TypeK8sDocker,
				},
				{
					Name:      "registry.k8s.io/nginx2-slim",
					Version:   "0.21",
					Locations: []string{"testdata/web.yaml"},
					PURLType:  purl.TypeK8sDocker,
				},
			},
		},
		{
			name:         "larger than size limit",
			path:         "testdata/deployment.yaml",
			cfg:          k8simage.Config{MaxFileSizeBytes: 1},
			wantPackages: nil,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			extr := k8simage.New(tc.cfg)

			input := extracttest.GenerateScanInputMock(t, extracttest.ScanInputMockConfig{
				Path: tc.path,
			})
			defer extracttest.CloseTestScanInput(t, input)

			got, err := extr.Extract(context.Background(), &input)
			if err != nil {
				t.Fatalf("%s.Extract(%q) failed: %v", extr.Name(), tc.path, err)
			}

			wantInv := inventory.Inventory{Packages: tc.wantPackages}
			if diff := cmp.Diff(wantInv, got, cmpopts.SortSlices(extracttest.PackageCmpLess)); diff != "" {
				t.Errorf("%s.Extract(%q) diff (-want +got):\n%s", extr.Name(), tc.path, diff)
			}
		})
	}
}

func TestExtract_failures(t *testing.T) {
	tests := []struct {
		name string
		path string
	}{
		{
			name: "invalid YAML",
			path: "testdata/not-yaml.yaml",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			extr := k8simage.New(k8simage.DefaultConfig())

			input := extracttest.GenerateScanInputMock(t, extracttest.ScanInputMockConfig{
				Path: tc.path,
			})
			defer extracttest.CloseTestScanInput(t, input)

			_, err := extr.Extract(context.Background(), &input)
			if err == nil {
				t.Fatalf("Extract(): got nil, want err")
			}
		})
	}
}
