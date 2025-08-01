// Copyright 2025 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//	http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// Package fakeclient contains a fake implementation of the deps.dev client for testing purposes.
package fakeclient

import (
	"context"

	depsdevpb "deps.dev/api/v3"
	"github.com/google/osv-scalibr/enricher/license"
	"google.golang.org/grpc"
)

var _ license.Client = &fakeClient{}

type versionKey struct {
	System  depsdevpb.System
	Name    string
	Version string
}

type fakeClient struct {
	licenseMap map[versionKey][]string
}

// New return a new fakeclient using the provided licenses
func New(licenses map[*depsdevpb.VersionKey][]string) license.Client {
	licenseMap := map[versionKey][]string{}
	for k, v := range licenses {
		licenseMap[versionKey{System: k.System, Version: k.Version, Name: k.Name}] = v
	}
	return &fakeClient{licenseMap: licenseMap}
}

// GetVersion implements license.Client.
func (f *fakeClient) GetVersion(_ context.Context, in *depsdevpb.GetVersionRequest, _ ...grpc.CallOption) (*depsdevpb.Version, error) {
	k := versionKey{System: in.VersionKey.System, Version: in.VersionKey.Version, Name: in.VersionKey.Name}
	licenses := f.licenseMap[k]
	return &depsdevpb.Version{Licenses: licenses}, nil
}
