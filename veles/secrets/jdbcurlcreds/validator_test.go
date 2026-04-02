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

package jdbcurlcreds_test

import (
	"testing"

	"github.com/google/osv-scalibr/veles"
	"github.com/google/osv-scalibr/veles/secrets/jdbcurlcreds"
)

func TestValidator(t *testing.T) {
	validator := jdbcurlcreds.NewValidator()

	cases := []struct {
		name   string
		secret jdbcurlcreds.Credentials
		want   veles.ValidationStatus
	}{
		{
			name: "remote_hostname_is_valid",
			secret: jdbcurlcreds.Credentials{
				FullURL:      "jdbc:postgresql://admin:secret@db.example.com:5432/prod",
				DatabaseType: "postgresql",
				Host:         "db.example.com",
				IsRemoteHost: true,
			},
			want: veles.ValidationValid,
		},
		{
			name: "public_ip_is_valid",
			secret: jdbcurlcreds.Credentials{
				FullURL:      "jdbc:mysql://root:pass@203.0.113.50:3306/db",
				DatabaseType: "mysql",
				Host:         "203.0.113.50",
				IsRemoteHost: true,
			},
			want: veles.ValidationValid,
		},
		{
			name: "localhost_is_invalid",
			secret: jdbcurlcreds.Credentials{
				FullURL:      "jdbc:postgresql://user:pass@localhost:5432/devdb",
				DatabaseType: "postgresql",
				Host:         "localhost",
				IsRemoteHost: false,
			},
			want: veles.ValidationInvalid,
		},
		{
			name: "loopback_ip_is_invalid",
			secret: jdbcurlcreds.Credentials{
				FullURL:      "jdbc:mysql://root:pass@127.0.0.1:3306/testdb",
				DatabaseType: "mysql",
				Host:         "127.0.0.1",
				IsRemoteHost: false,
			},
			want: veles.ValidationInvalid,
		},
		{
			name: "private_ip_is_invalid",
			secret: jdbcurlcreds.Credentials{
				FullURL:      "jdbc:postgresql://admin:secret@192.168.1.100:5432/db",
				DatabaseType: "postgresql",
				Host:         "192.168.1.100",
				IsRemoteHost: false,
			},
			want: veles.ValidationInvalid,
		},
		{
			name: "private_10_ip_is_invalid",
			secret: jdbcurlcreds.Credentials{
				FullURL:      "jdbc:mysql://user:pass@10.0.0.5:3306/db",
				DatabaseType: "mysql",
				Host:         "10.0.0.5",
				IsRemoteHost: false,
			},
			want: veles.ValidationInvalid,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := validator.Validate(t.Context(), tc.secret)
			if err != nil {
				t.Fatalf("Validate() error: %v", err)
			}
			if got != tc.want {
				t.Errorf("Validate() = %v, want %v", got, tc.want)
			}
		})
	}
}
