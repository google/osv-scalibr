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

package grpcclient_test

import (
	"testing"

	pb "deps.dev/api/v3alpha"
	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/google/osv-scalibr/clients/depsdev/v1alpha1/grpcclient"
)

func TestDefaultConfig(t *testing.T) {
	tests := []struct {
		name string
		want *grpcclient.Config
	}{
		{
			name: "default_config",
			want: &grpcclient.Config{
				Address: "api.deps.dev:443",
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := grpcclient.DefaultConfig()
			if diff := cmp.Diff(tc.want, got); diff != "" {
				t.Errorf("DefaultConfig() returned an unexpected diff (-want +got): %v", diff)
			}
		})
	}
}

func TestNew(t *testing.T) {
	tests := []struct {
		name    string
		cfg     *grpcclient.Config
		want    pb.InsightsClient
		wantErr error
	}{
		{
			name:    "nil config",
			cfg:     nil,
			wantErr: grpcclient.ErrMalformedConfig,
		},
		{
			name:    "empty address",
			cfg:     &grpcclient.Config{Address: ""},
			wantErr: grpcclient.ErrMalformedConfig,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := grpcclient.New(tc.cfg)
			if !cmp.Equal(err, tc.wantErr, cmpopts.EquateErrors()) {
				t.Errorf("New(%v) returned an unexpected error: %v", tc.cfg, err)
			}
			if diff := cmp.Diff(tc.want, got); diff != "" {
				t.Errorf("New(%v) returned an unexpected diff (-want +got): %v", tc.cfg, diff)
			}
		})
	}
}
