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

package samreg

import (
	"slices"
	"strings"
	"testing"
)

func TestDecryptRC4Hash(t *testing.T) {
	tests := []struct {
		name         string
		rid          []byte
		syskey       []byte
		hash         []byte
		hashConstant []byte
		want         []byte
		wantErr      bool
		wantErrText  string
	}{
		{
			name:         "valid_input_decrypts",
			rid:          []byte("\xf4\x01\x00\x00"),
			syskey:       []byte("\x3d\x21\x2c\xe8\xa2\xda\x83\x43\xbd\xad\x1e\xf2\xcf\xb6\xb3\x1c"),
			hash:         []byte("\xed\x92\x87\x92\x78\x3b\x69\x2c\x21\x37\x49\xbc\xdb\xe3\x1a\xf5"),
			hashConstant: []byte("\x4e\x54\x50\x41\x53\x53\x57\x4f\x52\x44\x00"),
			want:         []byte("\x58\xa4\x78\x13\x5a\x93\xac\x3b\xf0\x58\xa5\xea\x0e\x8f\xdb\x71"),
		},
		{
			name:         "RID_too_short_returns_error",
			rid:          []byte(""),
			syskey:       []byte("\x3d\x21\x2c\xe8\xa2\xda\x83\x43\xbd\xad\x1e\xf2\xcf\xb6\xb3\x1c"),
			hash:         []byte("\xed\x92\x87\x92\x78\x3b\x69\x2c\x21\x37\x49\xbc\xdb\xe3\x1a\xf5"),
			hashConstant: []byte("\x4e\x54\x50\x41\x53\x53\x57\x4f\x52\x44\x00"),
			wantErr:      true,
			wantErrText:  errInvalidRIDSize.Error(),
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			hash, err := decryptRC4Hash(tc.rid, tc.syskey, tc.hash, tc.hashConstant)
			if (err != nil) != tc.wantErr {
				t.Errorf("decryptRC4Hash(...): unexpected error: %v", err)
			}

			if tc.wantErr {
				if !strings.Contains(err.Error(), tc.wantErrText) {
					t.Errorf("decryptRC4Hash(...): unexpected error, got: %v, want: %v", err, tc.wantErrText)
				}

				return
			}

			if !slices.Equal(hash, tc.want) {
				t.Errorf("decryptRC4Hash(...): unexpected result, got: %v, want: %v", hash, tc.want)
			}
		})
	}
}

func TestDecryptAESHash(t *testing.T) {
	tests := []struct {
		name        string
		rid         []byte
		syskey      []byte
		hash        []byte
		salt        []byte
		want        []byte
		wantErr     bool
		wantErrText string
	}{
		{
			name:   "valid_input_decrypts",
			rid:    []byte("\xf4\x01\x00\x00"),
			syskey: []byte("\xfc\xde\xe8\x3a\xc6\xc1\x4b\x28\xf5\x26\x50\x1f\xc6\xe8\xbb\xc3"),
			hash:   []byte("\x48\xf2\xb6\x8b\xd9\x06\xa2\xbd\xb2\xaf\x39\x1c\xe2\x60\x44\x56\x6b\x80\x62\xb6\x55\xf4\x2b\x05\x9d\xfb\x5c\x68\x55\x4a\x5b\xc3"),
			salt:   []byte("\xa3\x28\x48\xec\x7d\x73\x12\xec\x81\xeb\x50\xd0\x65\x09\x55\xd4"),
			want:   []byte("\x58\xa4\x78\x13\x5a\x93\xac\x3b\xf0\x58\xa5\xea\x0e\x8f\xdb\x71"),
		},
		{
			name:   "empty_hash_returns_empty",
			rid:    []byte("\xf4\x01\x00\x00"),
			syskey: []byte("\xfc\xde\xe8\x3a\xc6\xc1\x4b\x28\xf5\x26\x50\x1f\xc6\xe8\xbb\xc3"),
			hash:   []byte(""),
			salt:   []byte("\xa3\x28\x48\xec\x7d\x73\x12\xec\x81\xeb\x50\xd0\x65\x09\x55\xd4"),
			want:   []byte(""),
		},
		{
			name:        "empty_syskey_returns_error",
			rid:         []byte(""),
			syskey:      []byte(""),
			hash:        []byte("\x00"),
			wantErr:     true,
			wantErrText: "hash length not aligned with AES block size",
		},
		{
			name:        "RID_too_short_returns_error",
			rid:         []byte(""),
			syskey:      []byte("\xfc\xde\xe8\x3a\xc6\xc1\x4b\x28\xf5\x26\x50\x1f\xc6\xe8\xbb\xc3"),
			hash:        []byte("\x48\xf2\xb6\x8b\xd9\x06\xa2\xbd\xb2\xaf\x39\x1c\xe2\x60\x44\x56\x6b\x80\x62\xb6\x55\xf4\x2b\x05\x9d\xfb\x5c\x68\x55\x4a\x5b\xc3"),
			salt:        []byte("\xa3\x28\x48\xec\x7d\x73\x12\xec\x81\xeb\x50\xd0\x65\x09\x55\xd4"),
			wantErr:     true,
			wantErrText: errInvalidRIDSize.Error(),
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			hash, err := decryptAESHash(tc.rid, tc.syskey, tc.hash, tc.salt)
			if (err != nil) != tc.wantErr {
				t.Errorf("decryptAESHash(...): unexpected error: %v", err)
			}

			if tc.wantErr {
				if !strings.Contains(err.Error(), tc.wantErrText) {
					t.Errorf("decryptAESHash(...): unexpected error, got: %v, want: %v", err, tc.wantErrText)
				}

				return
			}

			if !slices.Equal(hash, tc.want) {
				t.Errorf("decryptAESHash(...): unexpected result, got: %v, want: %v", hash, tc.want)
			}
		})
	}
}
