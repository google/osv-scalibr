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
	// maxURLLength is an upper bound value for the length of a URL to be considered.
	// This helps limit the buffer size required for scanning.
	maxURLLength = 1_000
)

// Known database protocol prefixes that can appear without the "jdbc:" prefix.
var knownDBProtocols = []string{
	"mysql", "mysqlx", "mysql\\+srv",
	"postgresql", "postgres",
	"sqlserver",
	"oracle", "mariadb", "db2",
	"h2", "hsqldb", "derby", "sqlite",
}

var (
	// jdbcURLPattern matches JDBC-style connection URLs.
	// It matches:
	//   - jdbc:<protocol>://<rest>
	//   - jdbc:<protocol>:<subprotocol>://<rest>  (e.g. jdbc:mysql+srv:replication://...)
	//   - <known_protocol>://<rest>  (e.g. mysql+srv://..., mysqlx://...)
	// The sub-protocol after ":" must be a known keyword (replication or loadbalance).
	jdbcURLPattern = regexp.MustCompile(
		`(?i)(?:jdbc:)?(?:` + strings.Join(knownDBProtocols, "|") + `)(?:\+[a-zA-Z0-9]+)*(?::(?:replication|loadbalance))?://[^\s]+`,
	)

	// parenHostPattern matches (host=value) in parenthesized key=value syntax like
	// address=(host=myhost1)(port=3333)(key1=value1).
	// The value must NOT contain commas (to distinguish from comma-separated syntax).
	parenHostPattern = regexp.MustCompile(`\(host=([^),]+)\)`)

	// parenPortPattern matches (port=value) in parenthesized key=value syntax.
	parenPortPattern = regexp.MustCompile(`\(port=(\d+)\)`)
)

// JDBCHost represents a parsed host from a JDBC URL.
type JDBCHost struct {
	Host string
	Port string
}

// NewDetector creates and returns a new instance of the JDBC URL credentials detector.
func NewDetector() veles.Detector {
	return simpletoken.Detector{
		MaxLen: maxURLLength,
		Re:     jdbcURLPattern,
		FromMatch: func(b []byte) (veles.Secret, bool) {
			input := string(b)
			hosts := ExtractJDBCHosts(input)
			if len(hosts) == 0 {
				return nil, false
			}
			isLocal := true
			for _, h := range hosts {
				if !IsLocalHost(h.Host) {
					isLocal = false
					break
				}
			}
			return Credentials{FullURL: input, IsLocalDB: isLocal}, true
		},
	}
}

// ExtractJDBCHosts detects a JDBC URL in the input and extracts all hosts from it.
// It handles:
//   - Simple host: jdbc:postgresql://host:1234/database
//   - IPv6: jdbc:postgresql://[::1]:5740/accounting
//   - Multiple comma-separated hosts: jdbc:postgresql://host1:3306,host2:3307/database
//   - MySQL address syntax: jdbc:mysql://address=(host=myhost1)(port=3333)/db
//   - MySQL bracket syntax: jdbc:mysql://user:pass@[host1:1111,host2:2222]/db
//   - SQL Server semicolon syntax: jdbc:sqlserver://localhost;databaseName=...
func ExtractJDBCHosts(input string) []JDBCHost {
	rawURL := DetectJDBCURL(input)
	if rawURL == "" {
		return nil
	}
	return parseJDBCHosts(rawURL)
}

// DetectJDBCURL checks whether the input string contains a JDBC-style database URL
// and returns the matched URL string. Returns empty string if no match.
func DetectJDBCURL(input string) string {
	match := jdbcURLPattern.FindString(input)
	return match
}

// parseJDBCHosts parses hosts from a raw JDBC URL string.
// It normalizes the URL, extracts the scheme, and dispatches to the
// appropriate protocol-specific parser.
func parseJDBCHosts(rawURL string) []JDBCHost {
	// Step 1: Strip "jdbc:" prefix if present (case-insensitive).
	normalized, _ := strings.CutPrefix(strings.ToLower(rawURL), "jdbc:")

	// Step 2: Handle sub-protocols (e.g. "mysql+srv:replication://..." -> "mysql+srv://...")
	parts := strings.SplitN(normalized, "://", 2)
	if len(parts) != 2 {
		return nil
	}
	scheme := parts[0]
	rest := parts[1]

	// If a scheme contains ":", it has a sub-protocol like "mysql+srv:replication".
	// Keep only the first part for URL parsing.
	if colonIdx := strings.Index(scheme, ":"); colonIdx >= 0 {
		scheme = scheme[:colonIdx]
	}

	// Strip any "+suffix" from the scheme for protocol matching
	// (e.g. "mysql+srv" -> "mysql").
	baseScheme := scheme
	if plusIdx := strings.Index(baseScheme, "+"); plusIdx >= 0 {
		baseScheme = baseScheme[:plusIdx]
	}

	// Dispatch to protocol-specific parsers.
	switch baseScheme {
	case "mysql", "mysqlx", "mariadb":
		return parseMySQLHosts(rest)
	case "sqlserver":
		return parseSQLServerHosts(rest)
	case "postgresql", "postgres":
		return parsePostgresHosts(rest)
	default:
		// For other protocols (oracle, db2, h2, hsqldb, derby, sqlite),
		// use the generic host parser.
		return parseGenericHosts(rest)
	}
}

// parseMySQLHosts parses hosts from a MySQL/MariaDB JDBC URL.
// MySQL supports several host formats:
//   - Simple: mysql://host:port/db
//   - Comma-separated: mysql://host1:port1,host2:port2/db
//   - Bracket syntax: mysql://user:pass@[host1:port1,host2:port2]/db
//   - Parenthesized address: mysql://address=(host=myhost1)(port=3333)/db
//   - Parenthesized key-value: mysql://(host=myhost2,port=3333,key=val)/db
//   - Mixed: mysql://myhost1:2222,(host=myhost2,port=2222)/db
func parseMySQLHosts(rest string) []JDBCHost {
	// Strip userinfo (user:pass@) if present before host parsing.
	hostSection := rest
	if _, after, found := strings.Cut(rest, "@"); found {
		hostSection = after
	}

	// Check for a bracket-enclosed host list: [host1:port1,host2:port2]/db
	if strings.HasPrefix(hostSection, "[") && !strings.HasPrefix(hostSection, "[::") {
		return parseBracketHosts(hostSection)
	}

	// Extract the host section (everything before the first "/" that's outside parens).
	hostSection = extractHostSection(hostSection)

	// Check for MySQL parenthesized syntax.
	if strings.Contains(hostSection, "(") {
		return parseParenthesizedHosts(hostSection)
	}

	// Split by comma for multiple plain hosts.
	return parseCommaSeparatedHosts(hostSection)
}

// parsePostgresHosts parses hosts from a PostgreSQL JDBC URL.
// PostgreSQL supports:
//   - Simple: postgresql://host:port/db
//   - IPv6: postgresql://[::1]:5740/db
//   - Comma-separated: postgresql://host1:port1,host2:port2/db
//   - Query parameters: postgresql://host/db?user=fred&password=secret
func parsePostgresHosts(rest string) []JDBCHost {
	// Strip userinfo (user:pass@) if present before host parsing.
	hostSection := rest
	if _, after, found := strings.Cut(rest, "@"); found {
		hostSection = after
	}

	// Extract the host section (everything before the first "/").
	hostSection = extractHostSection(hostSection)

	// Split by comma for multiple plain hosts.
	return parseCommaSeparatedHosts(hostSection)
}

// parseSQLServerHosts parses hosts from SQL Server JDBC URL format.
// SQL Server uses semicolons: localhost:1433;databaseName=...;
// or serverName=... in the parameters.
func parseSQLServerHosts(rest string) []JDBCHost {
	// Split on semicolons.
	parts := strings.Split(rest, ";")
	var hosts []JDBCHost

	// The first part is typically the host[:port].
	if len(parts) > 0 && parts[0] != "" {
		h := parseHostPort(strings.TrimSpace(parts[0]))
		if h.Host != "" {
			hosts = append(hosts, h)
		}
	}

	// Check for the serverName parameter.
	for _, p := range parts[1:] {
		p = strings.TrimSpace(p)
		lower := strings.ToLower(p)
		if strings.HasPrefix(lower, "servername=") {
			val := p[len("serverName="):]
			// Handle instance names (host\instance).
			if bsIdx := strings.Index(val, `\`); bsIdx >= 0 {
				val = val[:bsIdx]
			}
			// For serverName, don't try to parse as host:port since the value
			// could be an IPv6 address. Just return the raw value as host.
			if val != "" {
				hosts = append(hosts, JDBCHost{Host: val})
			}
		}
	}

	return hosts
}

// parseGenericHosts parses hosts from JDBC URLs for protocols that don't have
// special syntax (oracle, db2, h2, hsqldb, derby, sqlite, etc.).
// It handles a simple host:port and comma-separated hosts.
func parseGenericHosts(rest string) []JDBCHost {
	// Strip userinfo (user:pass@) if present before host parsing.
	hostSection := rest
	if _, after, found := strings.Cut(rest, "@"); found {
		hostSection = after
	}

	// Extract the host section (everything before the first "/").
	hostSection = extractHostSection(hostSection)

	// Split by comma for multiple plain hosts.
	return parseCommaSeparatedHosts(hostSection)
}

// parseCommaSeparatedHosts splits a host section by commas and parses each
// host:port entry.
func parseCommaSeparatedHosts(hostSection string) []JDBCHost {
	hostParts := strings.Split(hostSection, ",")
	var hosts []JDBCHost
	for _, hp := range hostParts {
		hp = strings.TrimSpace(hp)
		if hp == "" {
			continue
		}
		h := parseHostPort(hp)
		if h.Host != "" {
			hosts = append(hosts, h)
		}
	}
	return hosts
}

// extractHostSection extracts the host portion from the rest of the URL,
// finding the first "/" that is outside parentheses.
func extractHostSection(s string) string {
	depth := 0
	for i := range len(s) {
		switch s[i] {
		case '(':
			depth++
		case ')':
			if depth > 0 {
				depth--
			}
		case '/':
			if depth == 0 {
				return s[:i]
			}
		}
	}
	return s
}

// parseBracketHosts parses hosts from MySQL bracket syntax: [host1:port1,host2:port2]
func parseBracketHosts(hostSection string) []JDBCHost {
	// Find the closing bracket.
	closeIdx := strings.Index(hostSection, "]")
	if closeIdx < 0 {
		return nil
	}
	inner := hostSection[1:closeIdx]

	// Check if it contains parenthesized syntax.
	if strings.Contains(inner, "(") {
		return parseParenthesizedHosts(inner)
	}

	// Split by comma.
	parts := strings.Split(inner, ",")
	var hosts []JDBCHost
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		h := parseHostPort(p)
		if h.Host != "" {
			hosts = append(hosts, h)
		}
	}
	return hosts
}

// parseParenthesizedHosts parses MySQL parenthesized host syntax.
// Handles:
//   - address=(host=myhost1)(port=3333)(key1=value1)  — parenthesized key=value pairs
//   - (host=myhost2,port=3333,key2=value2)  — comma-separated key=value inside parens
//   - (address=host:1111,priority=1,key1=value1)  — address= with host:port value inside parens
//   - myhost1:2222,(host=myhost2,port=2222)  — mixed plain and parenthesized
func parseParenthesizedHosts(section string) []JDBCHost {
	var hosts []JDBCHost

	// Split into top-level entries, respecting parentheses.
	entries := splitOutsideParens(section, ',')

	for _, entry := range entries {
		entry = strings.TrimSpace(entry)
		if entry == "" {
			continue
		}

		if !strings.Contains(entry, "(") {
			// Plain host:port entry.
			h := parseHostPort(entry)
			if h.Host != "" {
				hosts = append(hosts, h)
			}
			continue
		}

		// Check for address=(host=...)(port=...) syntax — multiple parens per entry.
		// This is the format: address=(host=myhost1)(port=3333)(key1=value1)
		if parenHostPattern.MatchString(entry) {
			hostMatches := parenHostPattern.FindAllStringSubmatch(entry, -1)
			portMatches := parenPortPattern.FindAllStringSubmatch(entry, -1)
			for i, hm := range hostMatches {
				h := JDBCHost{Host: hm[1]}
				if i < len(portMatches) {
					h.Port = portMatches[i][1]
				}
				hosts = append(hosts, h)
			}
			continue
		}

		// Handle single-paren entries: (key=value,key=value,...)
		inner := entry
		if strings.HasPrefix(inner, "(") {
			endIdx := strings.Index(inner, ")")
			if endIdx >= 0 {
				inner = inner[1:endIdx]
			}
		}

		// Try to extract from comma-separated key=value pairs inside parens.
		h := extractFromKeyValuePairs(inner)
		if h.Host != "" {
			hosts = append(hosts, h)
			continue
		}
	}

	return hosts
}

// extractFromKeyValuePairs extracts host and port from a comma-separated
// key=value string like "host=myhost2,port=3333,key2=value2" or
// "address=host:1111,priority=1,key1=value1".
func extractFromKeyValuePairs(s string) JDBCHost {
	kvPairs := strings.Split(s, ",")
	var h JDBCHost
	for _, kv := range kvPairs {
		kv = strings.TrimSpace(kv)
		key, val, found := strings.Cut(kv, "=")
		if !found {
			continue
		}
		key = strings.ToLower(key)
		switch key {
		case "host":
			h.Host = val
		case "port":
			h.Port = val
		case "address":
			// address=host:port
			parsed := parseHostPort(val)
			if parsed.Host != "" {
				h.Host = parsed.Host
				if parsed.Port != "" {
					h.Port = parsed.Port
				}
			}
		}
	}
	return h
}

// splitOutsideParens splits a string by the given separator, but only when
// the separator is not inside parentheses.
func splitOutsideParens(s string, sep byte) []string {
	var result []string
	depth := 0
	start := 0
	for i := range len(s) {
		switch s[i] {
		case '(':
			depth++
		case ')':
			if depth > 0 {
				depth--
			}
		case sep:
			if depth == 0 {
				result = append(result, s[start:i])
				start = i + 1
			}
		}
	}
	result = append(result, s[start:])
	return result
}

// parseHostPort parses a single host[:port] string, including IPv6 addresses.
func parseHostPort(s string) JDBCHost {
	s = strings.TrimSpace(s)
	if s == "" {
		return JDBCHost{}
	}

	// Try standard URL parsing for robustness (handles IPv6 etc.).
	u, err := url.Parse("dummy://" + s)
	if err == nil && u.Hostname() != "" {
		return JDBCHost{
			Host: u.Hostname(),
			Port: u.Port(),
		}
	}

	return JDBCHost{}
}

// IsLocalHost returns true if the given host string represents a local/private
// IP address or localhost hostname. This includes:
//   - 127.0.0.0/8 (IPv4 loopback)
//   - ::1 (IPv6 loopback)
//   - 10.0.0.0/8 (RFC 1918)
//   - 172.16.0.0/12 (RFC 1918)
//   - 192.168.0.0/16 (RFC 1918)
//   - fe80::/10 (IPv6 link-local)
//   - fc00::/7 (IPv6 unique local)
//   - "localhost" hostname
func IsLocalHost(host string) bool {
	// Check for "localhost" hostname (case-insensitive).
	if strings.EqualFold(host, "localhost") {
		return true
	}

	ip := net.ParseIP(host)
	if ip == nil {
		return false
	}

	return ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast()
}
