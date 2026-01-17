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

package baseimage

import (
	"context"
	"errors"

	grpcpb "deps.dev/api/v3alpha"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

var errNotFound = errors.New("chainID not found")

// Client is the interface for the deps.dev client.
type Client interface {
	QueryContainerImages(ctx context.Context, req *Request) (*Response, error)
}

// Request is the request for the deps.dev client.
type Request struct {
	ChainID string
}

// Response is the response for the deps.dev client.
type Response struct {
	Results []*Result
}

// Result is the result for the deps.dev client.
type Result struct {
	Repository string
}

// ClientGRPC is the GRPC client for the deps.dev client.
type ClientGRPC struct {
	client grpcpb.InsightsClient
}

// NewClientGRPC returns a new ClientGRPC.
func NewClientGRPC(client grpcpb.InsightsClient) *ClientGRPC {
	return &ClientGRPC{client: client}
}

// QueryContainerImages queries the deps.dev client for container images.
func (c *ClientGRPC) QueryContainerImages(ctx context.Context, req *Request) (*Response, error) {
	reqpb := makeReq(req.ChainID)
	resppb, err := c.client.QueryContainerImages(ctx, reqpb)
	if err != nil {
		if status.Code(err) == codes.NotFound {
			return nil, errNotFound
		}

		return nil, err
	}

	var results []*Result
	for _, result := range resppb.GetResults() {
		results = append(results, &Result{Repository: result.GetRepository()})
	}

	var resp *Response
	if len(results) > 0 {
		resp = &Response{Results: results}
	}

	return resp, nil
}
