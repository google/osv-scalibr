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

package packagedeprecation

import (
	"context"
	"errors"
	"fmt"

	grpcpb "deps.dev/api/v3alpha"
	"github.com/google/osv-scalibr/log"
)

const (
	maxBatchSize = 5000 // Per deps.dev API documentation.
)

// Client is the interface for the deps.dev client.
type Client interface {
	GetVersionBatch(ctx context.Context, req Request) (Response, error)
}

// Request is the request for the deps.dev client.
type Request struct {
	VersionKeys []VersionKey
}

// Response is the response for the deps.dev client.
type Response struct {
	Results map[VersionKey]bool
}

// VersionKey contains the components to query a package version on deps.dev.
type VersionKey struct {
	System  grpcpb.System
	Name    string
	Version string
}

// GRPCClient is the GRPC client for deps.dev.
type GRPCClient struct {
	client grpcpb.InsightsClient
}

// NewClient returns a new GRPCClient for deps.dev
func NewClient(c grpcpb.InsightsClient) *GRPCClient {
	return &GRPCClient{client: c}
}

// GetVersionBatch queries deps.dev for deprecation status for the given versions.
// It handles chunking requests to deps.dev based on maxDepsdevBatchSize, and pagination of results
// within each chunk.
func (c *GRPCClient) GetVersionBatch(ctx context.Context, req Request) (Response, error) {
	if c.client == nil {
		return Response{}, errors.New("deps.dev gRPC client not initialized")
	}

	results := make(map[VersionKey]bool)
	vers := req.VersionKeys

	for i := 0; i < len(vers); i += maxBatchSize {
		// Splitting list of package versions into chunks of 5000 (maxBatchSize).
		end := min(i+maxBatchSize, len(vers))
		chunk := vers[i:end]

		batchReq := makeBatchReq(chunk)

		// Handle pagination (if any) of the batch response.
		for {
			batchResp, err := c.client.GetVersionBatch(ctx, batchReq)
			if err != nil {
				return Response{}, fmt.Errorf("depsdev.GetVersionBatch failed: %w", err)
			}

			for _, resp := range batchResp.GetResponses() {
				// Version not found in deps.dev
				if resp.GetVersion() == nil {
					continue
				}

				// Using the version key from the request (instead of from responses.version) because the
				// package and version names might be canonicalized by deps.dev.
				reqVer := resp.GetRequest().GetVersionKey()
				ver := VersionKey{
					System:  reqVer.GetSystem(),
					Name:    reqVer.GetName(),
					Version: reqVer.GetVersion(),
				}
				results[ver] = resp.GetVersion().GetIsDeprecated()
			}

			if batchResp.GetNextPageToken() == "" {
				break
			}

			updateBatchReq(batchReq, batchResp.GetNextPageToken())
		}
	}

	log.Infof("Package deprecation enricher: Finished querying deps.dev for deprecation status. Number of results: %d", len(results))

	return Response{Results: results}, nil
}
