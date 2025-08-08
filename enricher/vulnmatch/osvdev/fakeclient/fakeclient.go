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

// Package fakeclient contains a fake implementation of the OSV.dev client for testing purposes.
package fakeclient

import (
	"context"
	"fmt"

	"github.com/google/osv-scalibr/enricher/vulnmatch/osvdev"
	"github.com/ossf/osv-schema/bindings/go/osvschema"
	bindings "osv.dev/bindings/go/osvdev"
)

type client struct {
	data map[string][]osvschema.Vulnerability
}

func New(data map[string][]osvschema.Vulnerability) osvdev.Client {
	return &client{
		data: data,
	}
}

// GetVulnByID implements osvdev.Client.
func (c *client) GetVulnByID(_ context.Context, id string) (*osvschema.Vulnerability, error) {
	for _, vulns := range c.data {
		for _, vv := range vulns {
			if vv.ID == id {
				return &vv, nil
			}
		}
	}
	return nil, fmt.Errorf("Vuln %q not found", id)
}

// Query implements osvdev.Client.
func (c *client) Query(_ context.Context, query *bindings.Query) (*bindings.Response, error) {
	key := fmt.Sprintf("%s:%s:%s", query.Package.Name, query.Version, query.Commit)
	return &bindings.Response{
		Vulns: c.data[key],
	}, nil
}

// QueryBatch implements osvdev.Client.
func (c *client) QueryBatch(ctx context.Context, queries []*bindings.Query) (*bindings.BatchedResponse, error) {
	res := &bindings.BatchedResponse{}

	for _, qq := range queries {
		if err := ctx.Err(); err != nil {
			return res, err
		}

		rsp, err := c.Query(ctx, qq)

		// TODO: check if an empty result is appended in case of error
		if err != nil {
			return res, err
		}

		vulns := []bindings.MinimalVulnerability{}
		for _, vv := range rsp.Vulns {
			vulns = append(vulns, bindings.MinimalVulnerability{ID: vv.ID})
		}

		// TODO: check if the result is appended if len(vulns) == 0

		res.Results = append(res.Results, bindings.MinimalResponse{Vulns: vulns})
	}

	return res, nil
}
