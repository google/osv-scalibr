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

package proto

import (
	"github.com/google/osv-scalibr/result"

	spb "github.com/google/osv-scalibr/binary/proto/scan_result_go_proto"
	"google.golang.org/protobuf/types/known/timestamppb"
)

// --- Struct to Proto

// ScanResultToProto converts a ScanResult go struct into the equivalent proto.
func ScanResultToProto(r *result.ScanResult) (*spb.ScanResult, error) {
	pluginStatus := make([]*spb.PluginStatus, 0, len(r.PluginStatus))
	for _, s := range r.PluginStatus {
		pluginStatus = append(pluginStatus, PluginStatusToProto(s))
	}

	inventory, err := InventoryToProto(&r.Inventory)
	if err != nil {
		return nil, err
	}

	return &spb.ScanResult{
		Version:      r.Version,
		StartTime:    timestamppb.New(r.StartTime),
		EndTime:      timestamppb.New(r.EndTime),
		Status:       scanStatusToProto(r.Status),
		PluginStatus: pluginStatus,
		// TODO(b/400910349): Stop setting the deprecated fields
		// once integrators no longer read them.
		InventoriesDeprecated: inventory.GetPackages(),
		FindingsDeprecated:    inventory.GetGenericFindings(),
		Inventory:             inventory,
	}, nil
}

// --- Proto to Struct
