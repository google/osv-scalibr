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

// Package jdbcurlcreds contains the logic to extract JDBC URLs with credentials.
//
// JDBC URLs are connection strings used by Java applications to connect to
// databases. They may contain embedded credentials (username and password)
// which pose a security risk if exposed, particularly when the database
// host is publicly accessible.
//
// Supported database types:
//   - PostgreSQL: jdbc:postgresql://host:port/db?user=x&password=y
//   - MySQL/MariaDB: jdbc:mysql://user:pass@host:port/db
//   - SQL Server: jdbc:sqlserver://host:port;user=x;password=y
package jdbcurlcreds

// Credentials contains a JDBC URL with embedded credentials.
type Credentials struct {
	// FullURL is the complete JDBC URL as found in the source.
	FullURL string
	// DatabaseType is the type of database (e.g. "postgresql", "mysql", "sqlserver", "mariadb").
	DatabaseType string
	// Host is the database host extracted from the JDBC URL.
	Host string
	// IsRemoteHost indicates whether the database host is publicly accessible.
	// This is true for hostnames (other than "localhost") and public IP addresses.
	// Private IPs (10.x, 172.16-31.x, 192.168.x) and loopback addresses are
	// considered local.
	IsRemoteHost bool
}
