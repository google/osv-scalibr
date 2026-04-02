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

package jdbcurlcreds

import (
	"net"
	"net/url"
	"regexp"
	"strings"

	"github.com/google/osv-scalibr/veles"
	"github.com/google/osv-scalibr/veles/secrets/common/simpletoken"
)

const (
	// maxURLLength is an upper bound for the length of a JDBC URL.
	maxURLLength = 1_000
)

var (
	// jdbcPattern matches JDBC URLs.
	// Format: jdbc:<subprotocol>://<rest>
	// Captures URLs starting with jdbc: followed by a sub-protocol and connection details.
	jdbcPattern = regexp.MustCompile(`\bjdbc:[a-zA-Z0-9:]+//[^\s'"` + "`" + `]+`)
)

// NewDetector creates and returns a new instance of the JDBC URL credentials detector.
func NewDetector() veles.Detector {
	return simpletoken.Detector{
		MaxLen: maxURLLength,
		Re:     jdbcPattern,
		FromMatch: func(b []byte) (veles.Secret, bool) {
			s := string(b)
			creds, ok := parseJDBC(s)
			if !ok {
				return nil, false
			}
			return creds, true
		},
	}
}

// parseJDBC parses a JDBC URL and extracts credentials.
// Returns the Credentials and true if credentials were found.
func parseJDBC(raw string) (Credentials, bool) {
	dbType := extractDatabaseType(raw)
	if dbType == "" {
		return Credentials{}, false
	}

	var username, password, host string
	var hasCreds bool

	switch dbType {
	case "sqlserver":
		host, username, password, hasCreds = parseSQLServer(raw)
	default:
		// PostgreSQL, MySQL, MariaDB use standard URL format after stripping jdbc: prefix.
		host, username, password, hasCreds = parseStandardJDBC(raw, dbType)
	}

	if !hasCreds {
		return Credentials{}, false
	}

	// username and password are extracted for credential detection but not
	// stored in the secret type to avoid exposing plain credentials.
	_ = username
	_ = password

	return Credentials{
		FullURL:      raw,
		DatabaseType: dbType,
		Host:         host,
		IsRemoteHost: isRemoteHost(host),
	}, true
}

// extractDatabaseType returns the database type from a JDBC URL.
func extractDatabaseType(raw string) string {
	// jdbc:<type>://...
	lower := strings.ToLower(raw)
	if strings.HasPrefix(lower, "jdbc:postgresql:") {
		return "postgresql"
	}
	if strings.HasPrefix(lower, "jdbc:mysql:") {
		return "mysql"
	}
	if strings.HasPrefix(lower, "jdbc:mariadb:") {
		return "mariadb"
	}
	if strings.HasPrefix(lower, "jdbc:sqlserver:") {
		return "sqlserver"
	}
	if strings.HasPrefix(lower, "jdbc:oracle:") {
		return "oracle"
	}
	return ""
}

// parseStandardJDBC parses PostgreSQL, MySQL, and MariaDB JDBC URLs.
// These follow a standard URL format after the jdbc:<type>: prefix.
// Credentials can be in the userinfo part (user:pass@host) or as query parameters.
func parseStandardJDBC(raw string, dbType string) (host, username, password string, hasCreds bool) {
	// Strip the "jdbc:<type>:" prefix to get a standard URL.
	// e.g. "jdbc:postgresql://host/db" -> "postgresql://host/db"
	prefix := "jdbc:" + dbType + ":"
	lower := strings.ToLower(raw)
	idx := strings.Index(lower, prefix)
	if idx < 0 {
		return "", "", "", false
	}
	standardURL := raw[idx+len(prefix):]

	u, err := url.Parse(standardURL)
	if err != nil {
		return "", "", "", false
	}

	host = u.Hostname()

	// Check userinfo (user:pass@host)
	if u.User != nil {
		username = u.User.Username()
		password, _ = u.User.Password()
		if username != "" || password != "" {
			return host, username, password, true
		}
	}

	// Check query parameters (e.g. ?user=x&password=y)
	q := u.Query()
	username = q.Get("user")
	if username == "" {
		username = q.Get("username")
	}
	password = q.Get("password")

	if username != "" || password != "" {
		return host, username, password, true
	}

	return "", "", "", false
}

// parseSQLServer parses SQL Server JDBC URLs.
// SQL Server uses semicolons for properties: jdbc:sqlserver://host:port;user=x;password=y
func parseSQLServer(raw string) (host, username, password string, hasCreds bool) {
	// Strip "jdbc:sqlserver:" prefix.
	lower := strings.ToLower(raw)
	idx := strings.Index(lower, "jdbc:sqlserver:")
	if idx < 0 {
		return "", "", "", false
	}
	rest := raw[idx+len("jdbc:sqlserver:"):]

	// Split by semicolons to extract properties.
	// rest format: //host:port;prop1=val1;prop2=val2
	parts := strings.Split(rest, ";")

	// First part contains the host: //host:port or //host
	if len(parts) > 0 {
		hostPart := strings.TrimPrefix(parts[0], "//")
		// Remove any trailing path.
		if slashIdx := strings.Index(hostPart, "/"); slashIdx >= 0 {
			hostPart = hostPart[:slashIdx]
		}
		// Remove port.
		if colonIdx := strings.LastIndex(hostPart, ":"); colonIdx >= 0 {
			host = hostPart[:colonIdx]
		} else {
			host = hostPart
		}
	}

	// Parse properties from remaining parts.
	for _, part := range parts[1:] {
		kv := strings.SplitN(part, "=", 2)
		if len(kv) != 2 {
			continue
		}
		key := strings.ToLower(strings.TrimSpace(kv[0]))
		val := strings.TrimSpace(kv[1])
		switch key {
		case "user", "username":
			username = val
		case "password":
			password = val
		}
	}

	if username != "" || password != "" {
		return host, username, password, true
	}
	return "", "", "", false
}

// isRemoteHost determines if a host is publicly accessible.
// Hostnames (other than "localhost") are assumed to be remote.
// IP addresses are checked against private and loopback ranges.
func isRemoteHost(host string) bool {
	if host == "" {
		return false
	}

	lower := strings.ToLower(host)
	if lower == "localhost" {
		return false
	}

	ip := net.ParseIP(host)
	if ip == nil {
		// It's a hostname (not an IP) — assume remote per reviewer guidance.
		return true
	}

	// Check if the IP is private or loopback.
	if ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() {
		return false
	}

	return true
}
