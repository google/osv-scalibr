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

package docker_test

import (
	"context"
	"testing"

	"github.com/docker/docker/api/types"
	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/google/osv-scalibr/extractor"
	"github.com/google/osv-scalibr/extractor/standalone"
	plugin "github.com/google/osv-scalibr/extractor/standalone/containers/docker"
	"github.com/google/osv-scalibr/extractor/standalone/containers/docker/fakeclient"
)

func TestExtract(t *testing.T) {
	tests := []struct {
		name string
		// ctrs values are extracted using `docker inspect <containerID>`
		// some fields of `types.Container` are omitted
		ctrs          []types.Container
		wantInventory []*extractor.Inventory
	}{
		{
			name:          "valid with no container",
			ctrs:          []types.Container{},
			wantInventory: []*extractor.Inventory{},
		},
		{
			name: "valid with one container",
			ctrs: []types.Container{
				{
					ID:         "3ea6adad2e94daf386e1d6c5960807b41f19da2333e8a6261065c1cb8e85ac81",
					Names:      []string{"redis_server"},
					Image:      "redis",
					ImageID:    "sha256:a8036f14f15ead9517115576fb4462894a000620c2be556410f6c24afb8a482b",
					Command:    "docker-entrypoint.sh redis-server",
					Created:    1742382918,
					Ports:      []types.Port{{IP: "127.0.0.1", PrivatePort: 6379, PublicPort: 1112, Type: "tcp"}},
					SizeRw:     0,
					SizeRootFs: 0,
					Labels:     map[string]string{},
					State:      "running",
					Status:     "Up 4 days",
				},
			},
			wantInventory: []*extractor.Inventory{
				{
					Name:    "redis",
					Version: "sha256:a8036f14f15ead9517115576fb4462894a000620c2be556410f6c24afb8a482b",
					Metadata: &plugin.Metadata{
						ImageName:   "redis",
						ImageDigest: "sha256:a8036f14f15ead9517115576fb4462894a000620c2be556410f6c24afb8a482b",
						ID:          "3ea6adad2e94daf386e1d6c5960807b41f19da2333e8a6261065c1cb8e85ac81",
						Ports:       []types.Port{{IP: "127.0.0.1", PrivatePort: 6379, PublicPort: 1112, Type: "tcp"}},
					},
				},
			},
		},
		{
			name: "valid with one container running",
			ctrs: []types.Container{
				{
					ID:      "3ea6adad2e94daf386e1d6c5960807b41f19da2333e8a6261065c1cb8e85ac81",
					Names:   []string{"redis_server"},
					Image:   "redis",
					ImageID: "sha256:a8036f14f15ead9517115576fb4462894a000620c2be556410f6c24afb8a482b",
					Command: "docker-entrypoint.sh redis-server",
					Created: 1742382918,
					Ports:   []types.Port{{IP: "127.0.0.1", PrivatePort: 6379, PublicPort: 1112, Type: "tcp"}},
					Labels:  map[string]string{},
					State:   "running",
					Status:  "Up 4 days",
				},
				{
					ID:      "57eaa9ded450bde6c214dfdced8897d6bb67f1611fa6befffc7a768b5d1cbc5a",
					Names:   []string{"postgres_server"},
					Image:   "postgres",
					ImageID: "sha256:e92968df83750a723114bf998e3e323dda53e4c5c3ea42b22dd6ad6e3df80ca5",
					Command: "docker-entrypoint.sh postgres",
					Created: 1742814002,
					Ports:   []types.Port{},
					Labels:  map[string]string{},
					State:   "exited",
					Status:  "Exited (1) 2 minutes ago",
				},
			},
			wantInventory: []*extractor.Inventory{
				{
					Name:    "redis",
					Version: "sha256:a8036f14f15ead9517115576fb4462894a000620c2be556410f6c24afb8a482b",
					Metadata: &plugin.Metadata{
						ImageName:   "redis",
						ImageDigest: "sha256:a8036f14f15ead9517115576fb4462894a000620c2be556410f6c24afb8a482b",
						ID:          "3ea6adad2e94daf386e1d6c5960807b41f19da2333e8a6261065c1cb8e85ac81",
						Ports:       []types.Port{{IP: "127.0.0.1", PrivatePort: 6379, PublicPort: 1112, Type: "tcp"}},
					},
				},
			},
		},
		{
			name: "valid two containers running",
			ctrs: []types.Container{
				{
					ID:      "3ea6adad2e94daf386e1d6c5960807b41f19da2333e8a6261065c1cb8e85ac81",
					Names:   []string{"redis_server"},
					Image:   "redis",
					ImageID: "sha256:a8036f14f15ead9517115576fb4462894a000620c2be556410f6c24afb8a482b",
					Command: "docker-entrypoint.sh redis-server",
					Created: 1742382918,
					Ports:   []types.Port{{IP: "127.0.0.1", PrivatePort: 6379, PublicPort: 1112, Type: "tcp"}},
					Labels:  map[string]string{},
					State:   "running",
					Status:  "Up 4 days",
				},
				{
					ID:      "57eaa9ded450bde6c214dfdced8897d6bb67f1611fa6befffc7a768b5d1cbc5a",
					Names:   []string{"postgres_server"},
					Image:   "postgres",
					ImageID: "sha256:e92968df83750a723114bf998e3e323dda53e4c5c3ea42b22dd6ad6e3df80ca5",
					Command: "docker-entrypoint.sh postgres",
					Created: 1742814376,
					Ports:   []types.Port{{IP: "", PrivatePort: 5432, PublicPort: 0, Type: "tcp"}},
					Labels:  map[string]string{},
					State:   "running",
					Status:  "Up 8 minutes",
				},
			},
			wantInventory: []*extractor.Inventory{
				{
					Name:    "redis",
					Version: "sha256:a8036f14f15ead9517115576fb4462894a000620c2be556410f6c24afb8a482b",
					Metadata: &plugin.Metadata{
						ImageName:   "redis",
						ImageDigest: "sha256:a8036f14f15ead9517115576fb4462894a000620c2be556410f6c24afb8a482b",
						ID:          "3ea6adad2e94daf386e1d6c5960807b41f19da2333e8a6261065c1cb8e85ac81",
						Ports:       []types.Port{{IP: "127.0.0.1", PrivatePort: 6379, PublicPort: 1112, Type: "tcp"}},
					},
				},
				{
					Name:    "postgres",
					Version: "sha256:e92968df83750a723114bf998e3e323dda53e4c5c3ea42b22dd6ad6e3df80ca5",
					Metadata: &plugin.Metadata{
						ImageName:   "postgres",
						ImageDigest: "sha256:e92968df83750a723114bf998e3e323dda53e4c5c3ea42b22dd6ad6e3df80ca5",
						ID:          "57eaa9ded450bde6c214dfdced8897d6bb67f1611fa6befffc7a768b5d1cbc5a",
						Ports:       []types.Port{{IP: "", PrivatePort: 5432, PublicPort: 0, Type: "tcp"}},
					},
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var input *standalone.ScanInput

			cli := fakeclient.New(tt.ctrs)
			e := plugin.NewWithClient(cli)

			got, _ := e.Extract(context.Background(), input)

			ignoreOrder := cmpopts.SortSlices(func(a, b *extractor.Inventory) bool {
				return a.Name < b.Name
			})
			if diff := cmp.Diff(tt.wantInventory, got, ignoreOrder); diff != "" {
				t.Errorf("Extract(%s) (-want +got):\n%s", tt.name, diff)
			}
		})
	}
}
