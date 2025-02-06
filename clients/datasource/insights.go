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

// Package datasource provides clients to fetch data from different APIs.
package datasource

import (
	"context"
	"crypto/x509"
	"fmt"
	"sync"
	"time"

	pb "deps.dev/api/v3"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
)

// CachedInsightsClient is a wrapper for InsightsClient that caches requests.
type CachedInsightsClient struct {
	pb.InsightsClient

	// cache fields
	mu                sync.Mutex
	cacheTimestamp    *time.Time
	packageCache      *RequestCache[packageKey, *pb.Package]
	versionCache      *RequestCache[versionKey, *pb.Version]
	requirementsCache *RequestCache[versionKey, *pb.Requirements]
}

// Comparable types to use as map keys for cache.
type packageKey struct {
	System pb.System
	Name   string
}

func makePackageKey(k *pb.PackageKey) packageKey {
	return packageKey{
		System: k.GetSystem(),
		Name:   k.GetName(),
	}
}

type versionKey struct {
	System  pb.System
	Name    string
	Version string
}

func makeVersionKey(k *pb.VersionKey) versionKey {
	return versionKey{
		System:  k.GetSystem(),
		Name:    k.GetName(),
		Version: k.GetVersion(),
	}
}

// NewCachedInsightsClient creates a CachedInsightsClient.
func NewCachedInsightsClient(addr string, userAgent string) (*CachedInsightsClient, error) {
	certPool, err := x509.SystemCertPool()
	if err != nil {
		return nil, fmt.Errorf("getting system cert pool: %w", err)
	}
	creds := credentials.NewClientTLSFromCert(certPool, "")
	dialOpts := []grpc.DialOption{grpc.WithTransportCredentials(creds)}

	if userAgent != "" {
		dialOpts = append(dialOpts, grpc.WithUserAgent(userAgent))
	}

	conn, err := grpc.NewClient(addr, dialOpts...)
	if err != nil {
		return nil, fmt.Errorf("dialling %q: %w", addr, err)
	}

	return &CachedInsightsClient{
		InsightsClient:    pb.NewInsightsClient(conn),
		packageCache:      NewRequestCache[packageKey, *pb.Package](),
		versionCache:      NewRequestCache[versionKey, *pb.Version](),
		requirementsCache: NewRequestCache[versionKey, *pb.Requirements](),
	}, nil
}

// GetPackage returns metadata about a package by querying deps.dev API.
func (c *CachedInsightsClient) GetPackage(ctx context.Context, in *pb.GetPackageRequest, opts ...grpc.CallOption) (*pb.Package, error) {
	return c.packageCache.Get(makePackageKey(in.GetPackageKey()), func() (*pb.Package, error) {
		return c.InsightsClient.GetPackage(ctx, in, opts...)
	})
}

// GetVersion returns metadata about a version by querying deps.dev API.
func (c *CachedInsightsClient) GetVersion(ctx context.Context, in *pb.GetVersionRequest, opts ...grpc.CallOption) (*pb.Version, error) {
	return c.versionCache.Get(makeVersionKey(in.GetVersionKey()), func() (*pb.Version, error) {
		return c.InsightsClient.GetVersion(ctx, in, opts...)
	})
}

// GetRequirements returns requirements of the given version by querying deps.dev API.
func (c *CachedInsightsClient) GetRequirements(ctx context.Context, in *pb.GetRequirementsRequest, opts ...grpc.CallOption) (*pb.Requirements, error) {
	return c.requirementsCache.Get(makeVersionKey(in.GetVersionKey()), func() (*pb.Requirements, error) {
		return c.InsightsClient.GetRequirements(ctx, in, opts...)
	})
}
