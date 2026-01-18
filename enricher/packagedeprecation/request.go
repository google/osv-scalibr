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
	grpcpb "deps.dev/api/v3alpha"
)

func makeBatchReq(vers []VersionKey) *grpcpb.GetVersionBatchRequest {
	reqs := make([]*grpcpb.GetVersionRequest, 0, len(vers))
	for _, ver := range vers {
		reqs = append(reqs, &grpcpb.GetVersionRequest{
			VersionKey: &grpcpb.VersionKey{
				System:  ver.System,
				Name:    ver.Name,
				Version: ver.Version,
			},
		})
	}

	return &grpcpb.GetVersionBatchRequest{
		Requests: reqs,
	}
}

func updateBatchReq(req *grpcpb.GetVersionBatchRequest, pageToken string) {
	req.PageToken = pageToken
}
