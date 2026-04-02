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
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/google/osv-scalibr/veles"
	"github.com/google/osv-scalibr/veles/secrets/jdbcurlcreds"
	"github.com/google/osv-scalibr/veles/velestest"
)

func TestDetectorAcceptance(t *testing.T) {
	velestest.AcceptDetector(
		t,
		jdbcurlcreds.NewDetector(),
		"jdbc:postgresql://user:password@db.example.com:5432/mydb",
		jdbcurlcreds.Credentials{
			FullURL:      "jdbc:postgresql://user:password@db.example.com:5432/mydb",
			DatabaseType: "postgresql",
			Host:         "db.example.com",
			IsRemoteHost: true,
		},
	)
}

func TestDetector_truePositives(t *testing.T) {
	engine, err := veles.NewDetectionEngine([]veles.Detector{jdbcurlcreds.NewDetector()})
	if err != nil {
		t.Fatal(err)
	}

	cases := []struct {
		name  string
		input string
		want  []veles.Secret
	}{
		{
			name:  "postgresql_userinfo",
			input: "jdbc:postgresql://admin:secret@db.example.com:5432/production",
			want: []veles.Secret{
				jdbcurlcreds.Credentials{
					FullURL:      "jdbc:postgresql://admin:secret@db.example.com:5432/production",
					DatabaseType: "postgresql",
					Host:         "db.example.com",
					IsRemoteHost: true,
				},
			},
		},
		{
			name:  "postgresql_query_params",
			input: "jdbc:postgresql://db.example.com:5432/mydb?user=admin&password=secret",
			want: []veles.Secret{
				jdbcurlcreds.Credentials{
					FullURL:      "jdbc:postgresql://db.example.com:5432/mydb?user=admin&password=secret",
					DatabaseType: "postgresql",
					Host:         "db.example.com",
					IsRemoteHost: true,
				},
			},
		},
		{
			name:  "mysql_userinfo",
			input: "jdbc:mysql://root:p4ssw0rd@mysql.prod.internal:3306/appdb",
			want: []veles.Secret{
				jdbcurlcreds.Credentials{
					FullURL:      "jdbc:mysql://root:p4ssw0rd@mysql.prod.internal:3306/appdb",
					DatabaseType: "mysql",
					Host:         "mysql.prod.internal",
					IsRemoteHost: true,
				},
			},
		},
		{
			name:  "mysql_query_params",
			input: "jdbc:mysql://mysql.example.com/db?user=root&password=secret&useSSL=true",
			want: []veles.Secret{
				jdbcurlcreds.Credentials{
					FullURL:      "jdbc:mysql://mysql.example.com/db?user=root&password=secret&useSSL=true",
					DatabaseType: "mysql",
					Host:         "mysql.example.com",
					IsRemoteHost: true,
				},
			},
		},
		{
			name:  "mariadb_userinfo",
			input: "jdbc:mariadb://user:pass@mariadb.example.com:3306/testdb",
			want: []veles.Secret{
				jdbcurlcreds.Credentials{
					FullURL:      "jdbc:mariadb://user:pass@mariadb.example.com:3306/testdb",
					DatabaseType: "mariadb",
					Host:         "mariadb.example.com",
					IsRemoteHost: true,
				},
			},
		},
		{
			name:  "sqlserver_semicolons",
			input: "jdbc:sqlserver://sql.example.com:1433;user=sa;password=MyStr0ngP@ss;databaseName=prod",
			want: []veles.Secret{
				jdbcurlcreds.Credentials{
					FullURL:      "jdbc:sqlserver://sql.example.com:1433;user=sa;password=MyStr0ngP@ss;databaseName=prod",
					DatabaseType: "sqlserver",
					Host:         "sql.example.com",
					IsRemoteHost: true,
				},
			},
		},
		{
			name:  "sqlserver_username_key",
			input: "jdbc:sqlserver://db.windows.net:1433;username=admin;password=secret",
			want: []veles.Secret{
				jdbcurlcreds.Credentials{
					FullURL:      "jdbc:sqlserver://db.windows.net:1433;username=admin;password=secret",
					DatabaseType: "sqlserver",
					Host:         "db.windows.net",
					IsRemoteHost: true,
				},
			},
		},
		{
			name:  "localhost_is_local",
			input: "jdbc:postgresql://user:password@localhost:5432/devdb",
			want: []veles.Secret{
				jdbcurlcreds.Credentials{
					FullURL:      "jdbc:postgresql://user:password@localhost:5432/devdb",
					DatabaseType: "postgresql",
					Host:         "localhost",
					IsRemoteHost: false,
				},
			},
		},
		{
			name:  "loopback_ip_is_local",
			input: "jdbc:mysql://root:pass@127.0.0.1:3306/testdb",
			want: []veles.Secret{
				jdbcurlcreds.Credentials{
					FullURL:      "jdbc:mysql://root:pass@127.0.0.1:3306/testdb",
					DatabaseType: "mysql",
					Host:         "127.0.0.1",
					IsRemoteHost: false,
				},
			},
		},
		{
			name:  "private_ip_is_local",
			input: "jdbc:postgresql://admin:secret@192.168.1.100:5432/db",
			want: []veles.Secret{
				jdbcurlcreds.Credentials{
					FullURL:      "jdbc:postgresql://admin:secret@192.168.1.100:5432/db",
					DatabaseType: "postgresql",
					Host:         "192.168.1.100",
					IsRemoteHost: false,
				},
			},
		},
		{
			name:  "private_10_ip_is_local",
			input: "jdbc:mysql://user:pass@10.0.0.5:3306/db",
			want: []veles.Secret{
				jdbcurlcreds.Credentials{
					FullURL:      "jdbc:mysql://user:pass@10.0.0.5:3306/db",
					DatabaseType: "mysql",
					Host:         "10.0.0.5",
					IsRemoteHost: false,
				},
			},
		},
		{
			name:  "public_ip_is_remote",
			input: "jdbc:postgresql://admin:secret@203.0.113.50:5432/prod",
			want: []veles.Secret{
				jdbcurlcreds.Credentials{
					FullURL:      "jdbc:postgresql://admin:secret@203.0.113.50:5432/prod",
					DatabaseType: "postgresql",
					Host:         "203.0.113.50",
					IsRemoteHost: true,
				},
			},
		},
		{
			name:  "rds_aws_hostname",
			input: "jdbc:postgresql://admin:secret@mydb.abc123.us-east-1.rds.amazonaws.com:5432/prod",
			want: []veles.Secret{
				jdbcurlcreds.Credentials{
					FullURL:      "jdbc:postgresql://admin:secret@mydb.abc123.us-east-1.rds.amazonaws.com:5432/prod",
					DatabaseType: "postgresql",
					Host:         "mydb.abc123.us-east-1.rds.amazonaws.com",
					IsRemoteHost: true,
				},
			},
		},
		{
			name:  "in_config_file",
			input: `spring.datasource.url=jdbc:mysql://dbuser:dbpass@db.prod.example.com:3306/app`,
			want: []veles.Secret{
				jdbcurlcreds.Credentials{
					FullURL:      "jdbc:mysql://dbuser:dbpass@db.prod.example.com:3306/app",
					DatabaseType: "mysql",
					Host:         "db.prod.example.com",
					IsRemoteHost: true,
				},
			},
		},
		{
			name:  "in_xml_config",
			input: `<property name="url" value="jdbc:postgresql://user:pass@pg.example.com:5432/db"/>`,
			want: []veles.Secret{
				jdbcurlcreds.Credentials{
					FullURL:      "jdbc:postgresql://user:pass@pg.example.com:5432/db",
					DatabaseType: "postgresql",
					Host:         "pg.example.com",
					IsRemoteHost: true,
				},
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := engine.Detect(t.Context(), strings.NewReader(tc.input))
			if err != nil {
				t.Errorf("Detect() error: %v, want nil", err)
			}
			if diff := cmp.Diff(tc.want, got, cmpopts.EquateEmpty()); diff != "" {
				t.Errorf("Detect() diff (-want +got):\n%s", diff)
			}
		})
	}
}

func TestDetector_trueNegatives(t *testing.T) {
	engine, err := veles.NewDetectionEngine([]veles.Detector{jdbcurlcreds.NewDetector()})
	if err != nil {
		t.Fatal(err)
	}

	cases := []struct {
		name  string
		input string
	}{
		{
			name:  "empty_input",
			input: "",
		},
		{
			name:  "plain_url_not_jdbc",
			input: "https://user:pass@example.com",
		},
		{
			name:  "jdbc_no_credentials",
			input: "jdbc:postgresql://db.example.com:5432/mydb",
		},
		{
			name:  "jdbc_no_password_no_user",
			input: "jdbc:mysql://db.example.com:3306/test",
		},
		{
			name:  "jdbc_unknown_subprotocol",
			input: "jdbc:unknowndb://user:pass@host:1234/db",
		},
		{
			name:  "sqlserver_no_credentials",
			input: "jdbc:sqlserver://host:1433;databaseName=mydb",
		},
		{
			name:  "not_a_url",
			input: "this is just some text about jdbc connections",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := engine.Detect(t.Context(), strings.NewReader(tc.input))
			if err != nil {
				t.Errorf("Detect() error: %v, want nil", err)
			}
			if diff := cmp.Diff([]veles.Secret(nil), got, cmpopts.EquateEmpty()); diff != "" {
				t.Errorf("Detect() diff (-want +got):\n%s", diff)
			}
		})
	}
}
