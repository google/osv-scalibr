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

// --- Struct to Proto

// PluginStatusToProto converts a plugin.Status go struct into the equivalent proto.
func PluginStatusToProto(s *plugin.Status) *spb.PluginStatus {
	return &spb.PluginStatus{
		Name:    s.Name,
		Version: int32(s.Version),
		Status:  scanStatusToProto(s.Status),
	}
}

func scanStatusToProto(s *plugin.ScanStatus) *spb.ScanStatus {
	var e spb.ScanStatus_ScanStatusEnum
	switch s.Status {
	case plugin.ScanStatusSucceeded:
		e = spb.ScanStatus_SUCCEEDED
	case plugin.ScanStatusPartiallySucceeded:
		e = spb.ScanStatus_PARTIALLY_SUCCEEDED
	case plugin.ScanStatusFailed:
		e = spb.ScanStatus_FAILED
	default:
		e = spb.ScanStatus_UNSPECIFIED
	}
	return &spb.ScanStatus{Status: e, FailureReason: s.FailureReason}
}

// --- Proto to Struct
