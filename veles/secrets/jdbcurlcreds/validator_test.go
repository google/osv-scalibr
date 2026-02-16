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
	"database/sql"
	"errors"
	"testing"

	sqlmock "github.com/DATA-DOG/go-sqlmock"
	"github.com/google/go-cmp/cmp"
	"github.com/google/osv-scalibr/veles/secrets/jdbcurlcreds"
)

func TestExtractJDBCComponents(t *testing.T) {
	cases := []struct {
		name    string
		url     string
		want    jdbcurlcreds.JDBCParsedURL
		wantErr bool
	}{
		// === PostgreSQL formats ===
		{
			name: "postgresql_simple_userinfo",
			url:  "jdbc:postgresql://postgres:mysecretpassword@localhost:5432/testdb",
			want: jdbcurlcreds.JDBCParsedURL{
				Protocol: "postgresql",
				Hosts:    []jdbcurlcreds.JDBCHost{{Host: "localhost", Port: "5432"}},
				Username: "postgres",
				Password: "mysecretpassword",
				Database: "testdb",
				FullURL:  "jdbc:postgresql://postgres:mysecretpassword@localhost:5432/testdb",
			},
		},
		{
			name: "postgresql_trust_auth_no_password",
			url:  "jdbc:postgresql://postgres@localhost:5433/testdb",
			want: jdbcurlcreds.JDBCParsedURL{
				Protocol: "postgresql",
				Hosts:    []jdbcurlcreds.JDBCHost{{Host: "localhost", Port: "5433"}},
				Username: "postgres",
				Password: "",
				Database: "testdb",
				FullURL:  "jdbc:postgresql://postgres@localhost:5433/testdb",
			},
		},
		{
			name: "postgresql_query_param_credentials",
			url:  "jdbc:postgresql://localhost:5432/testdb?user=postgres&password=mysecretpassword",
			want: jdbcurlcreds.JDBCParsedURL{
				Protocol: "postgresql",
				Hosts:    []jdbcurlcreds.JDBCHost{{Host: "localhost", Port: "5432"}},
				Username: "postgres",
				Password: "mysecretpassword",
				Database: "testdb",
				FullURL:  "jdbc:postgresql://localhost:5432/testdb?user=postgres&password=mysecretpassword",
			},
		},
		{
			name: "postgresql_multi_host",
			url:  "jdbc:postgresql://postgres:mysecretpassword@localhost:5432,localhost:5433/testdb",
			want: jdbcurlcreds.JDBCParsedURL{
				Protocol: "postgresql",
				Hosts: []jdbcurlcreds.JDBCHost{
					{Host: "localhost", Port: "5432"},
					{Host: "localhost", Port: "5433"},
				},
				Username: "postgres",
				Password: "mysecretpassword",
				Database: "testdb",
				FullURL:  "jdbc:postgresql://postgres:mysecretpassword@localhost:5432,localhost:5433/testdb",
			},
		},
		{
			name: "postgresql_no_jdbc_prefix",
			url:  "postgresql://postgres:mysecretpassword@localhost:5432/testdb",
			want: jdbcurlcreds.JDBCParsedURL{
				Protocol: "postgresql",
				Hosts:    []jdbcurlcreds.JDBCHost{{Host: "localhost", Port: "5432"}},
				Username: "postgres",
				Password: "mysecretpassword",
				Database: "testdb",
				FullURL:  "postgresql://postgres:mysecretpassword@localhost:5432/testdb",
			},
		},
		{
			name: "postgresql_ipv6_host",
			url:  "jdbc:postgresql://postgres:mysecretpassword@[::1]:5432/testdb",
			want: jdbcurlcreds.JDBCParsedURL{
				Protocol: "postgresql",
				Hosts:    []jdbcurlcreds.JDBCHost{{Host: "::1", Port: "5432"}},
				Username: "postgres",
				Password: "mysecretpassword",
				Database: "testdb",
				FullURL:  "jdbc:postgresql://postgres:mysecretpassword@[::1]:5432/testdb",
			},
		},
		// === MySQL formats ===
		{
			name: "mysql_simple_userinfo",
			url:  "jdbc:mysql://username:password@localhost:3306/testdb",
			want: jdbcurlcreds.JDBCParsedURL{
				Protocol: "mysql",
				Hosts:    []jdbcurlcreds.JDBCHost{{Host: "localhost", Port: "3306"}},
				Username: "username",
				Password: "password",
				Database: "testdb",
				FullURL:  "jdbc:mysql://username:password@localhost:3306/testdb",
			},
		},
		{
			name: "mysql_no_password",
			url:  "jdbc:mysql://root@localhost:3307/testdb",
			want: jdbcurlcreds.JDBCParsedURL{
				Protocol: "mysql",
				Hosts:    []jdbcurlcreds.JDBCHost{{Host: "localhost", Port: "3307"}},
				Username: "root",
				Password: "",
				Database: "testdb",
				FullURL:  "jdbc:mysql://root@localhost:3307/testdb",
			},
		},
		{
			name: "mysql_query_param_credentials",
			url:  "jdbc:mysql://localhost:3306/testdb?user=username&password=password",
			want: jdbcurlcreds.JDBCParsedURL{
				Protocol: "mysql",
				Hosts:    []jdbcurlcreds.JDBCHost{{Host: "localhost", Port: "3306"}},
				Username: "username",
				Password: "password",
				Database: "testdb",
				FullURL:  "jdbc:mysql://localhost:3306/testdb?user=username&password=password",
			},
		},
		{
			name: "mysql_address_syntax",
			url:  "jdbc:mysql://address=(host=localhost)(port=3307)/testdb",
			want: jdbcurlcreds.JDBCParsedURL{
				Protocol: "mysql",
				Hosts:    []jdbcurlcreds.JDBCHost{{Host: "localhost", Port: "3307"}},
				Username: "",
				Password: "",
				Database: "testdb",
				FullURL:  "jdbc:mysql://address=(host=localhost)(port=3307)/testdb",
			},
		},
		{
			name: "mysql_parenthesized_key_value",
			url:  "jdbc:mysql://(host=localhost,port=3307)/testdb",
			want: jdbcurlcreds.JDBCParsedURL{
				Protocol: "mysql",
				Hosts:    []jdbcurlcreds.JDBCHost{{Host: "localhost", Port: "3307"}},
				Username: "",
				Password: "",
				Database: "testdb",
				FullURL:  "jdbc:mysql://(host=localhost,port=3307)/testdb",
			},
		},
		{
			name: "mysql_bracket_multi_host",
			url:  "jdbc:mysql://username:password@[localhost:3306,localhost:3307]/testdb",
			want: jdbcurlcreds.JDBCParsedURL{
				Protocol: "mysql",
				Hosts: []jdbcurlcreds.JDBCHost{
					{Host: "localhost", Port: "3306"},
					{Host: "localhost", Port: "3307"},
				},
				Username: "username",
				Password: "password",
				Database: "testdb",
				FullURL:  "jdbc:mysql://username:password@[localhost:3306,localhost:3307]/testdb",
			},
		},
		{
			name: "mysql_bracket_address_syntax",
			url:  "jdbc:mysql://username:password@[address=(host=localhost)(port=3306),address=(host=localhost)(port=3307)]/testdb",
			want: jdbcurlcreds.JDBCParsedURL{
				Protocol: "mysql",
				Hosts: []jdbcurlcreds.JDBCHost{
					{Host: "localhost", Port: "3306"},
					{Host: "localhost", Port: "3307"},
				},
				Username: "username",
				Password: "password",
				Database: "testdb",
				FullURL:  "jdbc:mysql://username:password@[address=(host=localhost)(port=3306),address=(host=localhost)(port=3307)]/testdb",
			},
		},
		{
			name: "mysql_mixed_plain_and_parenthesized",
			url:  "jdbc:mysql://root:@localhost:3306,(host=localhost,port=3307)/testdb",
			want: jdbcurlcreds.JDBCParsedURL{
				Protocol: "mysql",
				Hosts: []jdbcurlcreds.JDBCHost{
					{Host: "localhost", Port: "3306"},
					{Host: "localhost", Port: "3307"},
				},
				Username: "root",
				Password: "",
				Database: "testdb",
				FullURL:  "jdbc:mysql://root:@localhost:3306,(host=localhost,port=3307)/testdb",
			},
		},
		{
			name: "mysql_srv_scheme",
			url:  "jdbc:mysql+srv://username:password@localhost:3306/testdb",
			want: jdbcurlcreds.JDBCParsedURL{
				Protocol: "mysql+srv",
				Hosts:    []jdbcurlcreds.JDBCHost{{Host: "localhost", Port: "3306"}},
				Username: "username",
				Password: "password",
				Database: "testdb",
				FullURL:  "jdbc:mysql+srv://username:password@localhost:3306/testdb",
			},
		},
		{
			name: "mysql_srv_replication_sub_protocol",
			url:  "jdbc:mysql+srv:replication://username:password@localhost:3306/testdb",
			want: jdbcurlcreds.JDBCParsedURL{
				Protocol: "mysql+srv",
				Hosts:    []jdbcurlcreds.JDBCHost{{Host: "localhost", Port: "3306"}},
				Username: "username",
				Password: "password",
				Database: "testdb",
				FullURL:  "jdbc:mysql+srv:replication://username:password@localhost:3306/testdb",
			},
		},
		{
			name: "mysql_srv_no_jdbc_prefix",
			url:  "mysql+srv://username:password@localhost:3306/testdb",
			want: jdbcurlcreds.JDBCParsedURL{
				Protocol: "mysql+srv",
				Hosts:    []jdbcurlcreds.JDBCHost{{Host: "localhost", Port: "3306"}},
				Username: "username",
				Password: "password",
				Database: "testdb",
				FullURL:  "mysql+srv://username:password@localhost:3306/testdb",
			},
		},
		{
			name: "mysqlx_scheme",
			url:  "mysqlx://username:password@localhost:3306/testdb",
			want: jdbcurlcreds.JDBCParsedURL{
				Protocol: "mysqlx",
				Hosts:    []jdbcurlcreds.JDBCHost{{Host: "localhost", Port: "3306"}},
				Username: "username",
				Password: "password",
				Database: "testdb",
				FullURL:  "mysqlx://username:password@localhost:3306/testdb",
			},
		},
		// === SQL Server formats ===
		{
			name: "sqlserver_semicolon_params_with_port",
			url:  "jdbc:sqlserver://localhost:1433;databaseName=master;user=sa;password=YourStr0ngP@ss;encrypt=true;trustServerCertificate=true;",
			want: jdbcurlcreds.JDBCParsedURL{
				Protocol: "sqlserver",
				Hosts:    []jdbcurlcreds.JDBCHost{{Host: "localhost", Port: "1433"}},
				Username: "sa",
				Password: "YourStr0ngP@ss",
				Database: "master",
				FullURL:  "jdbc:sqlserver://localhost:1433;databaseName=master;user=sa;password=YourStr0ngP@ss;encrypt=true;trustServerCertificate=true;",
			},
		},
		{
			name: "sqlserver_without_port",
			url:  "jdbc:sqlserver://localhost;user=sa;password=YourStr0ngP@ss;encrypt=true;trustServerCertificate=true;",
			want: jdbcurlcreds.JDBCParsedURL{
				Protocol: "sqlserver",
				Hosts:    []jdbcurlcreds.JDBCHost{{Host: "localhost", Port: ""}},
				Username: "sa",
				Password: "YourStr0ngP@ss",
				Database: "",
				FullURL:  "jdbc:sqlserver://localhost;user=sa;password=YourStr0ngP@ss;encrypt=true;trustServerCertificate=true;",
			},
		},
		// === Error cases ===
		{
			name:    "invalid_url",
			url:     "not-a-jdbc-url",
			wantErr: true,
		},
		{
			name:    "unsupported_protocol",
			url:     "jdbc:oracle://localhost:1521/testdb",
			wantErr: true,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := jdbcurlcreds.ExtractJDBCComponents(tc.url)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("ExtractJDBCComponents(%q) expected error, got nil", tc.url)
				}
				return
			}
			if err != nil {
				t.Fatalf("ExtractJDBCComponents(%q) unexpected error: %v", tc.url, err)
			}
			if diff := cmp.Diff(tc.want, got); diff != "" {
				t.Errorf("ExtractJDBCComponents(%q) diff (-want +got):\n%s", tc.url, diff)
			}
		})
	}
}

// newFailingOpenFunc creates an SQLOpenFunc that always returns the given error,
// simulating a sql.Open failure.
func newFailingOpenFunc(err error) jdbcurlcreds.SQLOpenFunc {
	return func(_, _ string) (*sql.DB, error) {
		return nil, err
	}
}

func TestRealSQLDBConnectorConnectSingleHost(t *testing.T) {
	cases := []struct {
		name      string
		parsed    jdbcurlcreds.JDBCParsedURL
		setupMock func(mock sqlmock.Sqlmock)
		openFunc  func(db *sql.DB) jdbcurlcreds.SQLOpenFunc
		wantErr   bool
		errSubstr string
	}{
		{
			name: "postgresql_ping_success",
			parsed: jdbcurlcreds.JDBCParsedURL{
				Protocol: "postgresql",
				Hosts:    []jdbcurlcreds.JDBCHost{{Host: "localhost", Port: "5432"}},
				Username: "admin",
				Password: "secret",
				Database: "testdb",
			},
			setupMock: func(mock sqlmock.Sqlmock) {
				mock.ExpectPing()
			},
		},
		{
			name: "postgresql_ping_failure",
			parsed: jdbcurlcreds.JDBCParsedURL{
				Protocol: "postgresql",
				Hosts:    []jdbcurlcreds.JDBCHost{{Host: "localhost", Port: "5432"}},
				Username: "admin",
				Password: "wrong",
				Database: "testdb",
			},
			setupMock: func(mock sqlmock.Sqlmock) {
				mock.ExpectPing().WillReturnError(errors.New("authentication failed"))
			},
			wantErr:   true,
			errSubstr: "ping failed",
		},
		{
			name: "postgresql_default_port_and_user",
			parsed: jdbcurlcreds.JDBCParsedURL{
				Protocol: "postgresql",
				Hosts:    []jdbcurlcreds.JDBCHost{{Host: "dbhost", Port: ""}},
				Username: "",
				Password: "secret",
				Database: "mydb",
			},
			setupMock: func(mock sqlmock.Sqlmock) {
				mock.ExpectPing()
			},
		},
		{
			name: "mysql_ping_success",
			parsed: jdbcurlcreds.JDBCParsedURL{
				Protocol: "mysql",
				Hosts:    []jdbcurlcreds.JDBCHost{{Host: "localhost", Port: "3306"}},
				Username: "myuser",
				Password: "mypass",
				Database: "mydb",
			},
			setupMock: func(mock sqlmock.Sqlmock) {
				mock.ExpectPing()
			},
		},
		{
			name: "mysql_ping_failure",
			parsed: jdbcurlcreds.JDBCParsedURL{
				Protocol: "mysql",
				Hosts:    []jdbcurlcreds.JDBCHost{{Host: "localhost", Port: "3306"}},
				Username: "myuser",
				Password: "wrong",
				Database: "mydb",
			},
			setupMock: func(mock sqlmock.Sqlmock) {
				mock.ExpectPing().WillReturnError(errors.New("access denied"))
			},
			wantErr:   true,
			errSubstr: "ping failed",
		},
		{
			name: "mysql_default_port_and_user",
			parsed: jdbcurlcreds.JDBCParsedURL{
				Protocol: "mysql",
				Hosts:    []jdbcurlcreds.JDBCHost{{Host: "dbhost", Port: ""}},
				Username: "",
				Password: "secret",
				Database: "mydb",
			},
			setupMock: func(mock sqlmock.Sqlmock) {
				mock.ExpectPing()
			},
		},
		{
			name: "sqlserver_ping_success",
			parsed: jdbcurlcreds.JDBCParsedURL{
				Protocol: "sqlserver",
				Hosts:    []jdbcurlcreds.JDBCHost{{Host: "localhost", Port: "1433"}},
				Username: "sa",
				Password: "P@ssw0rd",
				Database: "master",
			},
			setupMock: func(mock sqlmock.Sqlmock) {
				mock.ExpectPing()
			},
		},
		{
			name: "sqlserver_ping_failure",
			parsed: jdbcurlcreds.JDBCParsedURL{
				Protocol: "sqlserver",
				Hosts:    []jdbcurlcreds.JDBCHost{{Host: "localhost", Port: "1433"}},
				Username: "sa",
				Password: "wrong",
				Database: "master",
			},
			setupMock: func(mock sqlmock.Sqlmock) {
				mock.ExpectPing().WillReturnError(errors.New("login failed"))
			},
			wantErr:   true,
			errSubstr: "ping failed",
		},
		{
			name: "sqlserver_default_port",
			parsed: jdbcurlcreds.JDBCParsedURL{
				Protocol: "sqlserver",
				Hosts:    []jdbcurlcreds.JDBCHost{{Host: "dbhost", Port: ""}},
				Username: "sa",
				Password: "secret",
				Database: "testdb",
			},
			setupMock: func(mock sqlmock.Sqlmock) {
				mock.ExpectPing()
			},
		},
		{
			name: "unsupported_protocol",
			parsed: jdbcurlcreds.JDBCParsedURL{
				Protocol: "oracle",
				Hosts:    []jdbcurlcreds.JDBCHost{{Host: "localhost", Port: "1521"}},
				Username: "admin",
				Password: "secret",
				Database: "testdb",
			},
			setupMock: nil, // no mock needed, should fail before sql.Open
			wantErr:   true,
			errSubstr: "unsupported protocol",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ctx := t.Context()

			// For unsupported protocol, no mock DB is needed.
			if tc.setupMock == nil {
				connector := &jdbcurlcreds.SQLDBConnector{
					OpenFunc: newFailingOpenFunc(errors.New("should not be called")),
				}
				err := connector.Connect(ctx, tc.parsed)
				if !tc.wantErr {
					t.Fatalf("Connect() unexpected error: %v", err)
				}
				if err == nil {
					t.Fatal("Connect() expected error, got nil")
				}
				if !contains(err.Error(), tc.errSubstr) {
					t.Errorf("Connect() error = %q, want substring %q", err.Error(), tc.errSubstr)
				}
				return
			}

			// Standard single-host tests using go-sqlmock.
			db, mock, err := sqlmock.New(sqlmock.MonitorPingsOption(true))
			if err != nil {
				t.Fatalf("failed to create sqlmock: %v", err)
			}
			defer func(db *sql.DB) {
				_ = db.Close()
			}(db)

			tc.setupMock(mock)

			connector := &jdbcurlcreds.SQLDBConnector{
				OpenFunc: func(_, _ string) (*sql.DB, error) { return db, nil },
			}

			err = connector.Connect(ctx, tc.parsed)

			if tc.wantErr {
				if err == nil {
					t.Fatal("Connect() expected error, got nil")
				}
				if tc.errSubstr != "" && !contains(err.Error(), tc.errSubstr) {
					t.Errorf("Connect() error = %q, want substring %q", err.Error(), tc.errSubstr)
				}
			} else if err != nil {
				t.Fatalf("Connect() unexpected error: %v", err)
			}

			if err := mock.ExpectationsWereMet(); err != nil {
				t.Errorf("unfulfilled sqlmock expectations: %v", err)
			}
		})
	}
}

func TestSQLDBConnectorConnectMultiHost(t *testing.T) {
	protocols := []struct {
		name   string
		parsed jdbcurlcreds.JDBCParsedURL
	}{
		{
			name: "postgresql",
			parsed: jdbcurlcreds.JDBCParsedURL{
				Protocol: "postgresql",
				Hosts: []jdbcurlcreds.JDBCHost{
					{Host: "host1", Port: "5432"},
					{Host: "host2", Port: "5432"},
				},
				Username: "admin",
				Password: "secret",
				Database: "testdb",
			},
		},
		{
			name: "mysql",
			parsed: jdbcurlcreds.JDBCParsedURL{
				Protocol: "mysql",
				Hosts: []jdbcurlcreds.JDBCHost{
					{Host: "host1", Port: "3306"},
					{Host: "host2", Port: "3306"},
				},
				Username: "root",
				Password: "secret",
				Database: "testdb",
			},
		},
		{
			name: "sqlserver",
			parsed: jdbcurlcreds.JDBCParsedURL{
				Protocol: "sqlserver",
				Hosts: []jdbcurlcreds.JDBCHost{
					{Host: "host1", Port: "1433"},
					{Host: "host2", Port: "1433"},
				},
				Username: "sa",
				Password: "secret",
				Database: "master",
			},
		},
	}

	for _, p := range protocols {
		t.Run(p.name+"/first_fails_second_succeeds", func(t *testing.T) {
			callCount := 0
			connector := &jdbcurlcreds.SQLDBConnector{
				OpenFunc: func(_, _ string) (*sql.DB, error) {
					callCount++
					db, mock, err := sqlmock.New(sqlmock.MonitorPingsOption(true))
					if err != nil {
						t.Fatalf("failed to create sqlmock: %v", err)
					}
					if callCount == 1 {
						mock.ExpectPing().WillReturnError(errors.New("host1 unreachable"))
					}
					if callCount == 2 {
						mock.ExpectPing()
					}
					return db, nil
				},
			}
			if err := connector.Connect(t.Context(), p.parsed); err != nil {
				t.Fatalf("Connect() unexpected error: %v", err)
			}
		})

		t.Run(p.name+"/all_fail", func(t *testing.T) {
			connector := &jdbcurlcreds.SQLDBConnector{
				OpenFunc: func(_, _ string) (*sql.DB, error) {
					db, mock, err := sqlmock.New(sqlmock.MonitorPingsOption(true))
					if err != nil {
						t.Fatalf("failed to create sqlmock: %v", err)
					}
					mock.ExpectPing().WillReturnError(errors.New("unreachable"))
					return db, nil
				},
			}
			err := connector.Connect(t.Context(), p.parsed)
			if err == nil {
				t.Fatal("Connect() expected error, got nil")
			}
			if !contains(err.Error(), "ping failed") {
				t.Errorf("Connect() error = %q, want substring %q", err.Error(), "ping failed")
			}
		})
	}
}

func TestSQLDBConnectorConnectOpenFailure(t *testing.T) {
	connector := &jdbcurlcreds.SQLDBConnector{
		OpenFunc: newFailingOpenFunc(errors.New("driver not found")),
	}

	parsed := jdbcurlcreds.JDBCParsedURL{
		Protocol: "postgresql",
		Hosts:    []jdbcurlcreds.JDBCHost{{Host: "localhost", Port: "5432"}},
		Username: "admin",
		Password: "secret",
		Database: "testdb",
	}

	err := connector.Connect(t.Context(), parsed)
	if err == nil {
		t.Fatal("Connect() expected error for sql.Open failure, got nil")
	}
	if !contains(err.Error(), "sql.Open failed") {
		t.Errorf("Connect() error = %q, want substring %q", err.Error(), "sql.Open failed")
	}
}

// contains checks if s contains substr.
func contains(s, substr string) bool {
	return len(s) >= len(substr) && searchSubstring(s, substr)
}

func searchSubstring(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}
