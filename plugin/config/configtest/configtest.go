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

// Package configtest provides fake implementations of config.ClientFactories for testing.
package configtest

import (
	"context"
	"net/http"

	cpb "github.com/google/osv-scalibr/binary/proto/config_go_proto"
	"github.com/google/osv-scalibr/plugin/config"
	"google.golang.org/grpc"
)

// FakeClientFactories implements config.ClientFactories for testing.
type FakeClientFactories struct {
	FakeHTTPClient       *http.Client
	FakeGoogleHTTPClient *http.Client
	FakeGRPCConn         grpc.ClientConnInterface
}

// NewFakeClientFactories returns a new FakeClientFactories with defaults.
func NewFakeClientFactories() *FakeClientFactories {
	return &FakeClientFactories{
		FakeHTTPClient:       &http.Client{},
		FakeGoogleHTTPClient: &http.Client{},
		FakeGRPCConn:         &fakeGRPCConn{},
	}
}

// HTTPClient returns the fake HTTP client.
func (f *FakeClientFactories) HTTPClient() *http.Client {
	return f.FakeHTTPClient
}

// GRPCClientConn returns the fake gRPC connection.
func (f *FakeClientFactories) GRPCClientConn(url string, dialOpts ...grpc.DialOption) (grpc.ClientConnInterface, error) {
	return f.FakeGRPCConn, nil
}

// GoogleHTTPClient returns the fake Google HTTP client.
func (f *FakeClientFactories) GoogleHTTPClient(ctx context.Context, scope ...string) (*http.Client, error) {
	return f.FakeGoogleHTTPClient, nil
}

// Close is a no-op.
func (f *FakeClientFactories) Close() error {
	return nil
}

// NewFakePluginConfig returns a PluginConfig with fake client factories.
func NewFakePluginConfig() *config.PluginConfig {
	return &config.PluginConfig{
		ProtoConfig:     &cpb.PluginConfig{},
		ClientFactories: NewFakeClientFactories(),
	}
}

type fakeGRPCConn struct{}

func (f *fakeGRPCConn) Invoke(ctx context.Context, method string, args any, reply any, opts ...grpc.CallOption) error {
	return nil
}

func (f *fakeGRPCConn) NewStream(ctx context.Context, desc *grpc.StreamDesc, method string, opts ...grpc.CallOption) (grpc.ClientStream, error) {
	return nil, nil
}
