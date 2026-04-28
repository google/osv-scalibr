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

// Package config provides configuration structures and client factories for plugins.
package config

import (
	"context"
	"crypto/x509"
	"net/http"

	cpb "github.com/google/osv-scalibr/binary/proto/config_go_proto"
	"golang.org/x/oauth2/google"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
)

// PluginConfig wraps the proto generated PluginConfig to allow passing arbitrary pointers/interfaces.
type PluginConfig struct {
	ProtoConfig     *cpb.PluginConfig
	ClientFactories ClientFactories
}

// ClientFactories defines methods to obtain shared clients and connections.
type ClientFactories interface {
	HTTPClient() *http.Client
	GRPCClientConn(url string, dialOpts ...grpc.DialOption) (grpc.ClientConnInterface, error)
	GoogleHTTPClient(scope ...string) (*http.Client, error)
}

// ClientFactoriesImpl provides a default implementation of ClientFactories.
type ClientFactoriesImpl struct {
	httpClient       *http.Client
	googleHTTPClient *http.Client
	grpcClientConns  map[string]*grpc.ClientConn
}

// NewClientFactoriesImpl returns a new ClientFactoriesImpl.
func NewClientFactoriesImpl() *ClientFactoriesImpl {
	return &ClientFactoriesImpl{
		grpcClientConns: make(map[string]*grpc.ClientConn),
	}
}

// HTTPClient returns a shared HTTP client.
func (c *ClientFactoriesImpl) HTTPClient() *http.Client {
	if c.httpClient == nil {
		c.httpClient = &http.Client{}
	}
	return c.httpClient
}

// GRPCClientConn returns a shared gRPC connection.
func (c *ClientFactoriesImpl) GRPCClientConn(url string, dialOpts ...grpc.DialOption) (grpc.ClientConnInterface, error) {
	if conn, ok := c.grpcClientConns[url]; ok {
		return conn, nil
	}

	certPool, err := x509.SystemCertPool()
	if err != nil {
		return nil, err
	}
	creds := credentials.NewClientTLSFromCert(certPool, "")
	ourDialOpts := []grpc.DialOption{grpc.WithTransportCredentials(creds)}
	ourDialOpts = append(ourDialOpts, dialOpts...)
	conn, err := grpc.NewClient(url, ourDialOpts...)
	if err != nil {
		return nil, err
	}

	c.grpcClientConns[url] = conn
	return conn, nil
}

// GoogleHTTPClient returns a shared HTTP client authenticated for Google services.
func (c *ClientFactoriesImpl) GoogleHTTPClient(scope ...string) (*http.Client, error) {
	if c.googleHTTPClient == nil {
		client, err := google.DefaultClient(context.Background(), scope...)
		if err != nil {
			return nil, err
		}
		c.googleHTTPClient = client
	}
	return c.googleHTTPClient, nil
}
