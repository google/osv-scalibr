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
	"github.com/google/osv-scalibr/plugin"

	spb "github.com/google/osv-scalibr/binary/proto/scan_result_go_proto"
)

var (
	// structToProtoScanStatus is a map of struct ScanStatus to their corresponding proto values.
	structToProtoScanStatus = map[plugin.ScanStatusEnum]spb.ScanStatus_ScanStatusEnum{
		plugin.ScanStatusSucceeded:          spb.ScanStatus_SUCCEEDED,
		plugin.ScanStatusPartiallySucceeded: spb.ScanStatus_PARTIALLY_SUCCEEDED,
		plugin.ScanStatusFailed:             spb.ScanStatus_FAILED,
		plugin.ScanStatusUnspecified:        spb.ScanStatus_UNSPECIFIED,
	}

	protoToStructScanStatus = func() map[spb.ScanStatus_ScanStatusEnum]plugin.ScanStatusEnum {
		m := make(map[spb.ScanStatus_ScanStatusEnum]plugin.ScanStatusEnum)
		for k, v := range structToProtoScanStatus {
			m[v] = k
		}
		if len(m) != len(structToProtoScanStatus) {
			panic("protoToStructScanStatus does not contain all values from structToProtoScanStatus")
		}
		return m
	}()
)

// --- Struct to Proto

// PluginStatusToProto converts a plugin.Status go struct into the equivalent proto.
func PluginStatusToProto(s *plugin.Status) *spb.PluginStatus {
	if s == nil {
		return nil
	}

	return &spb.PluginStatus{
		Name:    s.Name,
		Version: int32(s.Version),
		Status:  scanStatusToProto(s.Status),
	}
}

func scanStatusToProto(s *plugin.ScanStatus) *spb.ScanStatus {
	if s == nil {
		return nil
	}
	statusEnum := structToProtoScanStatus[s.Status]
	return &spb.ScanStatus{Status: statusEnum, FailureReason: s.FailureReason}
}

// --- Proto to Struct

// PluginStatusToStruct converts a plugin.Status proto into the equivalent go struct.
func PluginStatusToStruct(s *spb.PluginStatus) *plugin.Status {
	if s == nil {
		return nil
	}

	return &plugin.Status{
		Name:    s.GetName(),
		Version: int(s.GetVersion()),
		Status:  scanStatusToStruct(s.GetStatus()),
	}
}

func scanStatusToStruct(s *spb.ScanStatus) *plugin.ScanStatus {
	if s == nil {
		return nil
	}
	statusEnum := protoToStructScanStatus[s.GetStatus()]
	return &plugin.ScanStatus{Status: statusEnum, FailureReason: s.GetFailureReason()}
}
