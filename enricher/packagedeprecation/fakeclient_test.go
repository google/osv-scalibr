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

package packagedeprecation_test

import (
	"context"

	"github.com/google/osv-scalibr/enricher/packagedeprecation"
)

var _ packagedeprecation.Client = &fakeClient{}

type fakeClient struct {
	deprecationMap map[packagedeprecation.VersionKey]bool
}

func newFakeClient(depMap map[packagedeprecation.VersionKey]bool) fakeClient {
	client := fakeClient{deprecationMap: depMap}
	return client
}

func (c *fakeClient) GetVersionBatch(ctx context.Context, req packagedeprecation.Request) (packagedeprecation.Response, error) {
	results := make(map[packagedeprecation.VersionKey]bool)
	for _, ver := range req.VersionKeys {
		results[ver] = c.deprecationMap[ver]
	}
	return packagedeprecation.Response{Results: results}, nil
}
