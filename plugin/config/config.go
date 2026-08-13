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
	"errors"
	"fmt"
	"net/http"
	"slices"
	"strings"
	"sync"

	cpb "github.com/google/osv-scalibr/binary/proto/config_go_proto"
	"github.com/google/osv-scalibr/log"
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
	GoogleHTTPClient(ctx context.Context, scope ...string) (*http.Client, error)
}

// DefaultClientFactories provides a default implementation of ClientFactories.
type DefaultClientFactories struct {
	mu                sync.Mutex
	userAgent         string
	httpClient        *http.Client
	googleHTTPClients map[string]*http.Client
	grpcClientConns   map[string]*grpc.ClientConn
}

// NewDefaultClientFactories returns a new DefaultClientFactories.
func NewDefaultClientFactories(userAgent string) *DefaultClientFactories {
	return &DefaultClientFactories{
		userAgent:         userAgent,
		googleHTTPClients: make(map[string]*http.Client),
		grpcClientConns:   make(map[string]*grpc.ClientConn),
	}
}

// DefaultPluginConfig returns a PluginConfig with default client factories.
func DefaultPluginConfig() *PluginConfig {
	return &PluginConfig{
		ProtoConfig:     &cpb.PluginConfig{},
		ClientFactories: NewDefaultClientFactories(""),
	}
}

type userAgentRoundTripper struct {
	underlying http.RoundTripper
	userAgent  string
}

func (rt *userAgentRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	if req.Header.Get("User-Agent") == "" {
		req = req.Clone(req.Context())
		req.Header.Set("User-Agent", rt.userAgent)
	}
	underlying := rt.underlying
	if underlying == nil {
		underlying = http.DefaultTransport
	}
	return underlying.RoundTrip(req)
}

// HTTPClient returns a shared HTTP client.
func (c *DefaultClientFactories) HTTPClient() *http.Client {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.httpClient == nil {
		c.httpClient = &http.Client{}
		if c.userAgent != "" {
			c.httpClient.Transport = &userAgentRoundTripper{
				underlying: c.httpClient.Transport,
				userAgent:  c.userAgent,
			}
		}
	}
	return c.httpClient
}

// GRPCClientConn returns a shared gRPC connection.
func (c *DefaultClientFactories) GRPCClientConn(url string, dialOpts ...grpc.DialOption) (grpc.ClientConnInterface, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	// Note: If this url was already dialed, subsequent calls will return the cached
	// connection and ignore any new dialOpts. We assume that the factory won't
	// receive multiple different dial options for the same URL.
	if conn, ok := c.grpcClientConns[url]; ok {
		if len(dialOpts) > 0 {
			log.Warnf("GRPCClientConn: returning cached connection for %s, ignoring new dial options", url)
		}
		return conn, nil
	}

	certPool, err := x509.SystemCertPool()
	if err != nil {
		return nil, err
	}
	creds := credentials.NewClientTLSFromCert(certPool, "")
	ourDialOpts := []grpc.DialOption{grpc.WithTransportCredentials(creds)}
	if c.userAgent != "" {
		ourDialOpts = append(ourDialOpts, grpc.WithUserAgent(c.userAgent))
	}
	ourDialOpts = append(ourDialOpts, dialOpts...)
	conn, err := grpc.NewClient(url, ourDialOpts...)
	if err != nil {
		return nil, err
	}

	c.grpcClientConns[url] = conn
	return conn, nil
}

// GoogleHTTPClient returns a shared HTTP client authenticated for Google services.
func (c *DefaultClientFactories) GoogleHTTPClient(ctx context.Context, scope ...string) (*http.Client, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	// Sort and join scopes to create a unique cache key.
	sortedScopes := make([]string, len(scope))
	copy(sortedScopes, scope)
	slices.Sort(sortedScopes)
	key := strings.Join(sortedScopes, ",")

	if client, ok := c.googleHTTPClients[key]; ok {
		return client, nil
	}

	client, err := google.DefaultClient(ctx, scope...)
	if err != nil {
		return nil, err
	}
	if c.userAgent != "" {
		client.Transport = &userAgentRoundTripper{
			underlying: client.Transport,
			userAgent:  c.userAgent,
		}
	}
	c.googleHTTPClients[key] = client
	return client, nil
}

// Close closes all managed gRPC connections and idle HTTP connections.
func (c *DefaultClientFactories) Close() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	var errs []error
	for url, conn := range c.grpcClientConns {
		if err := conn.Close(); err != nil {
			errs = append(errs, fmt.Errorf("failed to close connection to %s: %w", url, err))
		}
		delete(c.grpcClientConns, url)
	}

	if c.httpClient != nil {
		c.httpClient.CloseIdleConnections()
		c.httpClient = nil
	}

	for key, client := range c.googleHTTPClients {
		if client != nil {
			client.CloseIdleConnections()
		}
		delete(c.googleHTTPClients, key)
	}
	c.googleHTTPClients = nil

	return errors.Join(errs...)
}
