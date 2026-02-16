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
)

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
			name:  "jdbc_postgresql_simple",
			input: "jdbc:postgresql://host:1234/database",
			want: []veles.Secret{
				jdbcurlcreds.Credentials{FullURL: "jdbc:postgresql://host:1234/database"},
			},
		},
		{
			name:  "jdbc_mysql_with_creds",
			input: "jdbc:mysql://localhost:3306/testdb?user=root&password=secret",
			want: []veles.Secret{
				jdbcurlcreds.Credentials{FullURL: "jdbc:mysql://localhost:3306/testdb?user=root&password=secret", IsLocalDB: true},
			},
		},
		{
			name:  "jdbc_mysql_srv_replication",
			input: "jdbc:mysql+srv:replication://host1:33060/sakila",
			want: []veles.Secret{
				jdbcurlcreds.Credentials{FullURL: "jdbc:mysql+srv:replication://host1:33060/sakila"},
			},
		},
		{
			name:  "mysql_srv_no_jdbc_prefix",
			input: "mysql+srv://host1:33060/sakila",
			want: []veles.Secret{
				jdbcurlcreds.Credentials{FullURL: "mysql+srv://host1:33060/sakila"},
			},
		},
		{
			name:  "jdbc_sqlserver",
			input: "jdbc:sqlserver://localhost:1433;encrypt=true;databaseName=AdventureWorks;integratedSecurity=true;",
			want: []veles.Secret{
				jdbcurlcreds.Credentials{FullURL: "jdbc:sqlserver://localhost:1433;encrypt=true;databaseName=AdventureWorks;integratedSecurity=true;", IsLocalDB: true},
			},
		},
		{
			name:  "jdbc_postgresql_ipv6",
			input: "jdbc:postgresql://[::1]:5740/accounting",
			want: []veles.Secret{
				jdbcurlcreds.Credentials{FullURL: "jdbc:postgresql://[::1]:5740/accounting", IsLocalDB: true},
			},
		},
		{
			name:  "jdbc_multiple_hosts",
			input: "jdbc:postgresql://host1:3306,host2:3307/database",
			want: []veles.Secret{
				jdbcurlcreds.Credentials{FullURL: "jdbc:postgresql://host1:3306,host2:3307/database"},
			},
		},
		{
			name:  "jdbc_mysql_address_syntax",
			input: "jdbc:mysql://address=(host=myhost1)(port=3333)(key1=value1)/db",
			want: []veles.Secret{
				jdbcurlcreds.Credentials{FullURL: "jdbc:mysql://address=(host=myhost1)(port=3333)(key1=value1)/db"},
			},
		},
		{
			name:  "jdbc_mysql_bracket_hosts",
			input: "jdbc:mysql://sandy:secret@[myhost1:5555,myhost2:5555]/db",
			want: []veles.Secret{
				jdbcurlcreds.Credentials{FullURL: "jdbc:mysql://sandy:secret@[myhost1:5555,myhost2:5555]/db"},
			},
		},
		{
			name:  "jdbc_postgresql_direct_ip",
			input: "jdbc:postgresql://203.0.113.50:5432/production",
			want: []veles.Secret{
				jdbcurlcreds.Credentials{FullURL: "jdbc:postgresql://203.0.113.50:5432/production"},
			},
		},
		{
			name:  "jdbc_mysql_private_ip",
			input: "jdbc:mysql://192.168.1.100:3306/testdb?user=root&password=secret",
			want: []veles.Secret{
				jdbcurlcreds.Credentials{FullURL: "jdbc:mysql://192.168.1.100:3306/testdb?user=root&password=secret", IsLocalDB: true},
			},
		},
		{
			name:  "jdbc_postgresql_loopback_ip",
			input: "jdbc:postgresql://127.0.0.1:5432/mydb",
			want: []veles.Secret{
				jdbcurlcreds.Credentials{FullURL: "jdbc:postgresql://127.0.0.1:5432/mydb", IsLocalDB: true},
			},
		},
		{
			name:  "jdbc_mysql_10_network_ip",
			input: "jdbc:mysql://10.0.0.5:3306/internal",
			want: []veles.Secret{
				jdbcurlcreds.Credentials{FullURL: "jdbc:mysql://10.0.0.5:3306/internal", IsLocalDB: true},
			},
		},
		{
			name:  "jdbc_postgresql_172_private_ip",
			input: "jdbc:postgresql://172.16.0.50:5432/staging",
			want: []veles.Secret{
				jdbcurlcreds.Credentials{FullURL: "jdbc:postgresql://172.16.0.50:5432/staging", IsLocalDB: true},
			},
		},
		{
			name:  "jdbc_multi_host_local_and_remote_is_not_local",
			input: "jdbc:mysql://localhost:3306,remote.example.com:3306/db?user=root&password=secret",
			want: []veles.Secret{
				jdbcurlcreds.Credentials{FullURL: "jdbc:mysql://localhost:3306,remote.example.com:3306/db?user=root&password=secret", IsLocalDB: false},
			},
		},
		{
			name:  "jdbc_multi_host_all_local_is_local",
			input: "jdbc:mysql://localhost:3306,127.0.0.1:3307/db?user=root&password=secret",
			want: []veles.Secret{
				jdbcurlcreds.Credentials{FullURL: "jdbc:mysql://localhost:3306,127.0.0.1:3307/db?user=root&password=secret", IsLocalDB: true},
			},
		},
		{
			name:  "jdbc_multi_host_all_remote_is_not_local",
			input: "jdbc:postgresql://db1.example.com:5432,db2.example.com:5432/production",
			want: []veles.Secret{
				jdbcurlcreds.Credentials{FullURL: "jdbc:postgresql://db1.example.com:5432,db2.example.com:5432/production", IsLocalDB: false},
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
		want  []veles.Secret
	}{
		{
			name:  "empty_input",
			input: "",
		},
		{
			name:  "plain_http_url",
			input: "http://example.com",
		},
		{
			name:  "https_url_not_jdbc",
			input: "https://example.com?email=user@gmail.com",
		},
		{
			name:  "random_text",
			input: "just some random text without any URLs",
		},
		{
			name:  "bad_url",
			input: "jdbc:postgresql:/db1.example.com:5432,db2.example.com:5432/production",
		},
		{
			name:  "no_protocol",
			input: "://db1.example.com:5432,db2.example.com:5432/production",
		},
		{
			name:  "no_protocol_2",
			input: "jdbc://db1.example.com:5432,db2.example.com:5432/production",
		},
		{
			name:  "no_host",
			input: "jdbc:mysql:///production",
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

func TestExtractJDBCHosts(t *testing.T) {
	cases := []struct {
		name  string
		input string
		want  []jdbcurlcreds.JDBCHost
	}{
		{
			name:  "simple_host_port_db",
			input: "jdbc:postgresql://host:1234/database",
			want:  []jdbcurlcreds.JDBCHost{{Host: "host", Port: "1234"}},
		},
		{
			name:  "host_no_port",
			input: "jdbc:postgresql://host/database",
			want:  []jdbcurlcreds.JDBCHost{{Host: "host"}},
		},
		{
			name:  "host_trailing_slash",
			input: "jdbc:postgresql://host/",
			want:  []jdbcurlcreds.JDBCHost{{Host: "host"}},
		},
		{
			name:  "ipv6_host",
			input: "jdbc:postgresql://[::1]:5740/accounting",
			want:  []jdbcurlcreds.JDBCHost{{Host: "::1", Port: "5740"}},
		},
		{
			name:  "host_with_query_params",
			input: "jdbc:postgresql://localhost/test?user=fred&password=secret&ssl=true",
			want:  []jdbcurlcreds.JDBCHost{{Host: "localhost"}},
		},
		{
			name:  "mysql_srv",
			input: "jdbc:mysql+srv://host1:33060/sakila",
			want:  []jdbcurlcreds.JDBCHost{{Host: "host1", Port: "33060"}},
		},
		{
			name:  "mysql_srv_replication",
			input: "jdbc:mysql+srv:replication://host1:33060/sakila",
			want:  []jdbcurlcreds.JDBCHost{{Host: "host1", Port: "33060"}},
		},
		{
			name:  "mysql_srv_replication_multiple_comma_separated_hosts",
			input: "jdbc:mysql+srv:replication://host1:3306,host2:3307/sakila",
			want: []jdbcurlcreds.JDBCHost{
				{Host: "host1", Port: "3306"},
				{Host: "host2", Port: "3307"}},
		},
		{
			name:  "no_jdbc_prefix",
			input: "mysql+srv://host1:33060/sakila",
			want:  []jdbcurlcreds.JDBCHost{{Host: "host1", Port: "33060"}},
		},
		{
			name:  "mysql_with_creds_query",
			input: "jdbc:mysql://localhost:3306/testdb?user=root&password=",
			want:  []jdbcurlcreds.JDBCHost{{Host: "localhost", Port: "3306"}},
		},
		{
			name:  "multiple_comma_separated_hosts",
			input: "jdbc:postgresql://host1:3306,host2:3307/database",
			want: []jdbcurlcreds.JDBCHost{
				{Host: "host1", Port: "3306"},
				{Host: "host2", Port: "3307"},
			},
		},
		{
			name:  "mysql_address_syntax",
			input: "jdbc:mysql://address=(host=myhost1)(port=3333)(key1=value1)/db",
			want:  []jdbcurlcreds.JDBCHost{{Host: "myhost1", Port: "3333"}},
		},
		{
			name:  "mysqlx_address_syntax",
			input: "mysqlx://(address=host:1111,priority=1,key1=value1)/db",
			want:  []jdbcurlcreds.JDBCHost{{Host: "host", Port: "1111"}},
		},
		{
			name:  "mixed_host_and_address",
			input: "jdbc:mysql://myhost1:2222,(host=myhost2,port=2222,key2=value2)/db",
			want: []jdbcurlcreds.JDBCHost{
				{Host: "myhost1", Port: "2222"},
				{Host: "myhost2", Port: "2222"},
			},
		},
		{
			name:  "address_host_only",
			input: "jdbc:mysql://(host=myhost2,port=3333,key2=value2)/db",
			want:  []jdbcurlcreds.JDBCHost{{Host: "myhost2", Port: "3333"}},
		},
		{
			name:  "multiple_address_entries",
			input: "mysqlx://(address=host1:4444,priority=1,key1=value1),(address=host2:4444,priority=2,key2=value2)/db",
			want: []jdbcurlcreds.JDBCHost{
				{Host: "host1", Port: "4444"},
				{Host: "host2", Port: "4444"},
			},
		},
		{
			name:  "bracket_hosts_with_creds",
			input: "jdbc:mysql://sandy:secret@[myhost1:5555,myhost2:5555]/db",
			want: []jdbcurlcreds.JDBCHost{
				{Host: "myhost1", Port: "5555"},
				{Host: "myhost2", Port: "5555"},
			},
		},
		{
			name:  "bracket_address_with_creds",
			input: "jdbc:mysql://sandy:secret@[address=(host=myhost1)(port=6666)(key1=value1),address=(host=myhost2)(port=6666)(key2=value2)]/db",
			want: []jdbcurlcreds.JDBCHost{
				{Host: "myhost1", Port: "6666"},
				{Host: "myhost2", Port: "6666"},
			},
		},
		{
			name:  "bracket_mixed_with_creds",
			input: "jdbc:mysql://sandy:secret@[myhost1:7777,address=(host=myhost2)(port=7777)(key2=value2)]/db",
			want: []jdbcurlcreds.JDBCHost{
				{Host: "myhost1", Port: "7777"},
				{Host: "myhost2", Port: "7777"},
			},
		},
		{
			name:  "sqlserver_simple",
			input: "jdbc:sqlserver://localhost;encrypt=true;user=MyUserName;password=<password>;",
			want:  []jdbcurlcreds.JDBCHost{{Host: "localhost"}},
		},
		{
			name:  "sqlserver_with_port",
			input: "jdbc:sqlserver://localhost:1433;encrypt=true;databaseName=AdventureWorks;integratedSecurity=true;",
			want:  []jdbcurlcreds.JDBCHost{{Host: "localhost", Port: "1433"}},
		},
		{
			name:  "sqlserver_servername_param",
			input: `jdbc:sqlserver://;serverName=3ffe:8311:eeee:f70f:0:5eae:10.203.31.9\\instance1;encrypt=true;integratedSecurity=true;`,
			want:  []jdbcurlcreds.JDBCHost{{Host: "3ffe:8311:eeee:f70f:0:5eae:10.203.31.9"}},
		},
		{
			name:  "direct_public_ip",
			input: "jdbc:postgresql://203.0.113.50:5432/production",
			want:  []jdbcurlcreds.JDBCHost{{Host: "203.0.113.50", Port: "5432"}},
		},
		{
			name:  "direct_private_ip_192",
			input: "jdbc:mysql://192.168.1.100:3306/testdb",
			want:  []jdbcurlcreds.JDBCHost{{Host: "192.168.1.100", Port: "3306"}},
		},
		{
			name:  "direct_loopback_ip",
			input: "jdbc:postgresql://127.0.0.1:5432/mydb",
			want:  []jdbcurlcreds.JDBCHost{{Host: "127.0.0.1", Port: "5432"}},
		},
		{
			name:  "direct_private_ip_10",
			input: "jdbc:mysql://10.0.0.5:3306/internal",
			want:  []jdbcurlcreds.JDBCHost{{Host: "10.0.0.5", Port: "3306"}},
		},
		{
			name:  "direct_private_ip_172",
			input: "jdbc:postgresql://172.16.0.50:5432/staging",
			want:  []jdbcurlcreds.JDBCHost{{Host: "172.16.0.50", Port: "5432"}},
		},
		{
			name:  "multiple_direct_ips",
			input: "jdbc:mysql://10.0.0.1:3306,10.0.0.2:3307/database",
			want: []jdbcurlcreds.JDBCHost{
				{Host: "10.0.0.1", Port: "3306"},
				{Host: "10.0.0.2", Port: "3307"},
			},
		},
		{
			name:  "no_match",
			input: "just some text",
			want:  nil,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := jdbcurlcreds.ExtractJDBCHosts(tc.input)
			if diff := cmp.Diff(tc.want, got); diff != "" {
				t.Errorf("ExtractJDBCHosts(%q) diff (-want +got):\n%s", tc.input, diff)
			}
		})
	}
}

func TestIsLocalHost_BoundaryRanges(t *testing.T) {
	cases := []struct {
		name string
		host string
		want bool
	}{
		// 127.0.0.0/8 (IPv4 loopback) boundaries
		{name: "loopback_start_127.0.0.0", host: "127.0.0.0", want: true},
		{name: "loopback_end_127.255.255.255", host: "127.255.255.255", want: true},
		{name: "before_loopback_126.255.255.255", host: "126.255.255.255", want: false},
		{name: "after_loopback_128.0.0.0", host: "128.0.0.0", want: false},

		// 10.0.0.0/8 (RFC 1918) boundaries
		{name: "private_10_start_10.0.0.0", host: "10.0.0.0", want: true},
		{name: "private_10_end_10.255.255.255", host: "10.255.255.255", want: true},
		{name: "before_private_10_9.255.255.255", host: "9.255.255.255", want: false},
		{name: "after_private_10_11.0.0.0", host: "11.0.0.0", want: false},

		// 172.16.0.0/12 (RFC 1918) boundaries
		{name: "private_172_start_172.16.0.0", host: "172.16.0.0", want: true},
		{name: "private_172_end_172.31.255.255", host: "172.31.255.255", want: true},
		{name: "before_private_172_172.15.255.255", host: "172.15.255.255", want: false},
		{name: "after_private_172_172.32.0.0", host: "172.32.0.0", want: false},

		// 192.168.0.0/16 (RFC 1918) boundaries
		{name: "private_192_start_192.168.0.0", host: "192.168.0.0", want: true},
		{name: "private_192_end_192.168.255.255", host: "192.168.255.255", want: true},
		{name: "before_private_192_192.167.255.255", host: "192.167.255.255", want: false},
		{name: "after_private_192_192.169.0.0", host: "192.169.0.0", want: false},

		// fe80::/10 (IPv6 link-local) boundaries
		{name: "link_local_ipv6_start_fe80::", host: "fe80::", want: true},
		{name: "link_local_ipv6_end_febf:ffff:...", host: "febf:ffff:ffff:ffff:ffff:ffff:ffff:ffff", want: true},
		{name: "before_link_local_ipv6_fe7f::", host: "fe7f::", want: false},
		{name: "after_link_local_ipv6_fec0::", host: "fec0::", want: false},

		// fc00::/7 (IPv6 unique local) boundaries
		{name: "unique_local_ipv6_start_fc00::", host: "fc00::", want: true},
		{name: "unique_local_ipv6_end_fdff:ffff:...", host: "fdff:ffff:ffff:ffff:ffff:ffff:ffff:ffff", want: true},
		{name: "before_unique_local_ipv6_fbff::", host: "fbff::", want: false},
		{name: "after_unique_local_ipv6_fe00::", host: "fe00::", want: false},

		// 169.254.0.0/16 (IPv4 link-local) — caught by IsLinkLocalUnicast() but not documented
		{name: "link_local_ipv4_169.254.0.1", host: "169.254.0.1", want: true},
		{name: "link_local_ipv4_169.254.255.255", host: "169.254.255.255", want: true},
		{name: "before_link_local_ipv4_169.253.255.255", host: "169.253.255.255", want: false},
		{name: "after_link_local_ipv4_169.255.0.0", host: "169.255.0.0", want: false},

		// IPv4-mapped IPv6 addresses (::ffff:x.x.x.x)
		{name: "mapped_ipv6_loopback_::ffff:127.0.0.1", host: "::ffff:127.0.0.1", want: true},
		{name: "mapped_ipv6_private_10_::ffff:10.0.0.1", host: "::ffff:10.0.0.1", want: true},
		{name: "mapped_ipv6_private_172_::ffff:172.16.0.1", host: "::ffff:172.16.0.1", want: true},
		{name: "mapped_ipv6_private_192_::ffff:192.168.1.1", host: "::ffff:192.168.1.1", want: true},
		{name: "mapped_ipv6_link_local_::ffff:169.254.1.1", host: "::ffff:169.254.1.1", want: true},
		{name: "mapped_ipv6_public_::ffff:8.8.8.8", host: "::ffff:8.8.8.8", want: false},
		{name: "mapped_ipv6_public_::ffff:203.0.113.50", host: "::ffff:203.0.113.50", want: false},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := jdbcurlcreds.IsLocalHost(tc.host)
			if got != tc.want {
				t.Errorf("IsLocalHost(%q) = %v, want %v", tc.host, got, tc.want)
			}
		})
	}
}
