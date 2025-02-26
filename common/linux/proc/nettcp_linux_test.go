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

//go:build linux

package proc

import (
	"context"
	"errors"
	"net"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"
)

func TestParseNetTCP(t *testing.T) {
	loopbackAddr := net.ParseIP("127.0.0.1")
	anyAddrV6 := net.ParseIP("::")
	tests := []struct {
		name    string
		content string
		want    *NetTCPInfo
		wantErr error
	}{
		{
			name: "empty",
			want: &NetTCPInfo{},
		},
		{
			name: "valid_ipv4_entries_returned",
			content: `sl local_address rem_address st tx_queue rx_queue tr tm->when retrnsmt uid timeout inode
0: 0100007F:1A29 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 25739 2 0000000000000000 100 0 0 10 0
1: 0100007F:2556 00000000:0000 01 00000000:00000000 00:00000000 00000000     0        0 10459 2 0000000000000000 100 0 0 10 0
`,
			want: &NetTCPInfo{
				Entries: []*NetTCPEntry{
					&NetTCPEntry{
						LocalAddr: &loopbackAddr,
						LocalPort: 0x1A29,
						State:     0xA,
						Inode:     25739,
					},
					&NetTCPEntry{
						LocalAddr: &loopbackAddr,
						LocalPort: 0x2556,
						State:     0x1,
						Inode:     10459,
					},
				},
			},
		},
		{
			name: "valid_ipv6_entries_returned",
			content: `sl  local_address                         remote_address                        st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
0: 00000000000000000000000000000000:312C 00000000000000000000000000000000:0000 0A 00000000:00000000 00:00000000 00000000   114        0 46168 1 0000000000000000 100 0 0 10 0
1: 00000000000000000000000000000000:312D 00000000000000000000000000000000:0000 01 00000000:00000000 00:00000000 00000000   114        0 4548 2 0000000000000000 100 0 0 10 0
`,
			want: &NetTCPInfo{
				Entries: []*NetTCPEntry{
					&NetTCPEntry{
						LocalAddr: &anyAddrV6,
						LocalPort: 0x312C,
						State:     0xA,
						Inode:     46168,
					},
					&NetTCPEntry{
						LocalAddr: &anyAddrV6,
						LocalPort: 0x312D,
						State:     0x1,
						Inode:     4548,
					},
				},
			},
		},
		{
			name: "invalid_file_format_returns_error",
			content: `
sl local_address rem_address st tx_queue rx_queue tr tm->when retrnsmt uid timeout inode
0: 0100007F:1A29`,
			wantErr: errInvalidFileFormat,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := ParseNetTCP(context.Background(), strings.NewReader(tc.content))
			if !errors.Is(err, tc.wantErr) {
				t.Fatalf("ParseNetTCP(...) returned an unexpected error: %v", err)
			}

			if tc.wantErr != nil {
				return
			}

			if diff := cmp.Diff(tc.want, got); diff != "" {
				t.Errorf("ParseNetTCP(...) returned an unexpected diff (-want +got): %v", diff)
			}
		})
	}
}
