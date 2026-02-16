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
	"context"
	"database/sql"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	_ "github.com/go-sql-driver/mysql" // Register MySQL driver for database/sql.
	"github.com/google/osv-scalibr/veles"
	_ "github.com/lib/pq"               // Register PostgreSQL driver for database/sql.
	_ "github.com/microsoft/go-mssqldb" // Register SQL Server driver for database/sql.
)

const (
	// connectTimeout is the maximum time to wait for a database connection attempt.
	connectTimeout = 5 * time.Second
)

// SQLOpenFunc is the function signature for sql.Open, allowing injection for testing.
type SQLOpenFunc func(driverName, dataSourceName string) (*sql.DB, error)

// DBConnector abstracts the database connection logic for testability.
type DBConnector interface {
	Connect(ctx context.Context, parsed JDBCParsedURL) error
}

// SQLDBConnector connects to databases using database/sql.
// OpenFunc can be overridden for testing (defaults to sql.Open).
type SQLDBConnector struct {
	OpenFunc SQLOpenFunc
}

// Validator is a URL credentials validator.
type Validator struct {
	Client    *http.Client
	Connector DBConnector
}

// NewValidator returns an URL credentials validator.
func NewValidator() veles.Validator[Credentials] {
	return &Validator{
		Client:    http.DefaultClient,
		Connector: &SQLDBConnector{OpenFunc: sql.Open},
	}
}

// Validate checks whether a JDBC URL credential is valid by extracting the
// connection components and attempting to connect to each host in the URL.
func (v *Validator) Validate(ctx context.Context, secret Credentials) (veles.ValidationStatus, error) {
	parsed, err := ExtractJDBCComponents(secret.FullURL)
	if err != nil {
		return veles.ValidationFailed, fmt.Errorf("error extracting JDBC components: %w", err)
	}

	if len(parsed.Hosts) == 0 {
		return veles.ValidationFailed, fmt.Errorf("no hosts extracted from URL: %s", secret.FullURL)
	}

	if err := v.Connector.Connect(ctx, parsed); err != nil {
		return veles.ValidationFailed, err
	}

	return veles.ValidationValid, nil
}

// ExtractJDBCComponents parses a JDBC URL and dispatches to the appropriate
// DB-specific extraction function based on the detected protocol.
// It supports PostgreSQL, MySQL, and SQL Server JDBC URL formats.
// The input is assumed to be a valid JDBC URL (already validated by the detector).
func ExtractJDBCComponents(rawURL string) (JDBCParsedURL, error) {
	// Normalize: strip "jdbc:" prefix, extract protocol and rest after "://".
	protocol, rest, ok := normalizeJDBCURL(rawURL)
	if !ok {
		return JDBCParsedURL{FullURL: rawURL}, fmt.Errorf("could not parse URL: %s", rawURL)
	}

	switch baseProtocol(protocol) {
	case "postgresql", "postgres":
		return extractPostgreSQLComponents(rawURL, protocol, rest), nil
	case "mysql", "mysqlx":
		return extractMySQLComponents(rawURL, protocol, rest), nil
	case "sqlserver":
		return extractSQLServerComponents(rawURL, protocol), nil
	default:
		return JDBCParsedURL{FullURL: rawURL}, fmt.Errorf("unsupported protocol %q in: %s", protocol, rawURL)
	}
}

// Connect attempts to connect to the database using the extracted JDBC components.
// It tries each host in order; if any one host connects successfully, it returns nil.
// Returns the last error if all hosts fail.
func (r *SQLDBConnector) Connect(ctx context.Context, parsed JDBCParsedURL) error {
	baseProto := baseProtocol(parsed.Protocol)

	var lastErr error
	for _, h := range parsed.Hosts {
		host := h.Host
		port := h.Port

		var driverName, dsn string

		switch baseProto {
		case "postgresql", "postgres":
			if port == "" {
				port = "5432"
			}
			pgUser := parsed.Username
			if pgUser == "" {
				pgUser = "postgres"
			}
			dsn = fmt.Sprintf("host=%s port=%s user=%s password=%s dbname=%s sslmode=disable",
				host, port, pgUser, parsed.Password, parsed.Database)
			driverName = "postgres"

		case "mysql", "mysqlx":
			if port == "" {
				port = "3306"
			}
			mysqlUser := parsed.Username
			if mysqlUser == "" {
				mysqlUser = "root"
			}
			dsn = fmt.Sprintf("%s:%s@tcp(%s:%s)/%s", mysqlUser, parsed.Password, host, port, parsed.Database)
			driverName = "mysql"

		case "sqlserver":
			if port == "" {
				port = "1433"
			}
			query := url.Values{}
			query.Set("database", parsed.Database)
			query.Set("encrypt", "disable")
			query.Set("TrustServerCertificate", "true")
			u := &url.URL{
				Scheme:   "sqlserver",
				User:     url.UserPassword(parsed.Username, parsed.Password),
				Host:     fmt.Sprintf("%s:%s", host, port),
				RawQuery: query.Encode(),
			}
			dsn = u.String()
			driverName = "sqlserver"

		default:
			return fmt.Errorf("unsupported protocol: %s", parsed.Protocol)
		}

		openFn := r.OpenFunc
		if openFn == nil {
			openFn = sql.Open
		}
		db, err := openFn(driverName, dsn)
		if err != nil {
			lastErr = fmt.Errorf("host %s:%s sql.Open failed: %w", host, port, err)
			continue
		}

		pingCtx, cancel := context.WithTimeout(ctx, connectTimeout)
		err = db.PingContext(pingCtx)
		cancel()
		_ = db.Close()

		if err == nil {
			return nil
		}
		lastErr = fmt.Errorf("host %s:%s ping failed: %w", host, port, err)
	}

	return lastErr
}

// JDBCParsedURL holds all extracted components from a JDBC URL.
type JDBCParsedURL struct {
	Protocol string
	Hosts    []JDBCHost
	Username string
	Password string
	Database string
	FullURL  string
}

// normalizeJDBCURL strips the "jdbc:" prefix (case-insensitive) and splits on "://"
// to return the scheme (protocol) and the rest of the URL. The scheme has any
// sub-protocol removed (e.g. "mysql+srv:replication" -> "mysql+srv").
func normalizeJDBCURL(rawURL string) (protocol, rest string, ok bool) {
	normalized, _ := strings.CutPrefix(strings.ToLower(rawURL), "jdbc:")
	parts := strings.SplitN(normalized, "://", 2)
	if len(parts) != 2 {
		return "", "", false
	}
	scheme := parts[0]
	// Remove sub-protocol (e.g. "mysql+srv:replication" -> "mysql+srv")
	if before, _, found := strings.Cut(scheme, ":"); found {
		scheme = before
	}
	return scheme, parts[1], true
}

// baseProtocol strips "+srv" or similar suffixes from a protocol string
// for base protocol matching (e.g. "mysql+srv" -> "mysql").
func baseProtocol(protocol string) string {
	if before, _, found := strings.Cut(protocol, "+"); found {
		return before
	}
	return protocol
}

// extractUserInfoCreds extracts username and password from the userinfo portion
// (user:pass@) of a URL rest string and sets them on the given JDBCParsedURL.
func extractUserInfoCreds(rest string, result *JDBCParsedURL) {
	if userinfo, _, found := strings.Cut(rest, "@"); found {
		if u, err := url.Parse("dummy://" + userinfo + "@host"); err == nil {
			result.Username = u.User.Username()
			result.Password, _ = u.User.Password()
		}
	}
}

// extractQueryParamCreds extracts username and password from query parameters
// (?user=...&password=...) and sets them on the given JDBCParsedURL, overriding
// any previously set userinfo credentials.
func extractQueryParamCreds(rest string, result *JDBCParsedURL) {
	if _, queryStr, found := strings.Cut(rest, "?"); found {
		params, _ := url.ParseQuery(queryStr)
		if u := params.Get("user"); u != "" {
			result.Username = u
		}
		if p := params.Get("password"); p != "" {
			result.Password = p
		}
	}
}

// stripUserInfo removes the userinfo portion (everything before "@") from the
// URL rest string, returning the host-and-path portion.
func stripUserInfo(rest string) string {
	if _, after, found := strings.Cut(rest, "@"); found {
		return after
	}
	return rest
}

// extractPostgreSQLComponents parses a PostgreSQL JDBC URL and extracts protocol,
// hosts, username, password, and database name.
// PostgreSQL credentials can appear as userinfo (user:pass@host) or as query
// parameters (?user=...&password=...). The database name is extracted from the
// URL path after the host section.
func extractPostgreSQLComponents(rawURL string, protocol, rest string) JDBCParsedURL {
	result := JDBCParsedURL{FullURL: rawURL, Protocol: protocol}
	result.Hosts = ExtractJDBCHosts(rawURL)

	// Extract credentials from userinfo (user:pass@).
	extractUserInfoCreds(rest, &result)

	// PostgreSQL supports query param credentials (?user=...&password=...) which
	// override userinfo credentials.
	extractQueryParamCreds(rest, &result)

	// Extract database name from the URL path (e.g. /testdb).
	hostAndPath := stripUserInfo(rest)
	if _, dbPart, found := strings.Cut(hostAndPath, "/"); found {
		if before, _, hasQuery := strings.Cut(dbPart, "?"); hasQuery {
			dbPart = before
		}
		result.Database = strings.TrimRight(dbPart, "/")
	}

	return result
}

// extractMySQLComponents parses a MySQL JDBC URL and extracts protocol,
// hosts, username, password, and database name.
// MySQL credentials can appear as userinfo (user:pass@host) or as query
// parameters (?user=...&password=...). The database name is extracted from the
// URL path, handling MySQL-specific bracket-enclosed hosts and parenthesized
// address syntax (e.g. address=(host=...)(port=...)).
func extractMySQLComponents(rawURL string, protocol, rest string) JDBCParsedURL {
	result := JDBCParsedURL{FullURL: rawURL, Protocol: protocol}
	result.Hosts = ExtractJDBCHosts(rawURL)

	// Extract credentials from userinfo (user:pass@).
	extractUserInfoCreds(rest, &result)

	// MySQL supports query param credentials (?user=...&password=...) which
	// override userinfo credentials.
	extractQueryParamCreds(rest, &result)

	// Extract database name from the URL path, handling MySQL-specific syntax:
	// bracket-enclosed hosts [host1:port1,host2:port2] and parenthesized addresses.
	hostAndPath := stripUserInfo(rest)
	// Strip bracket-enclosed host lists (not IPv6 brackets).
	if strings.HasPrefix(hostAndPath, "[") && !strings.HasPrefix(hostAndPath, "[::") {
		if _, after, found := strings.Cut(hostAndPath, "]"); found {
			hostAndPath = after
		}
	}
	// Find the first "/" outside parentheses to get the database path.
	depth := 0
	for i := range len(hostAndPath) {
		switch hostAndPath[i] {
		case '(':
			depth++
		case ')':
			if depth > 0 {
				depth--
			}
		case '/':
			if depth == 0 {
				dbPart := hostAndPath[i+1:]
				if before, _, found := strings.Cut(dbPart, "?"); found {
					dbPart = before
				}
				result.Database = strings.TrimRight(dbPart, "/")
				break
			}
		}
		if result.Database != "" {
			break
		}
	}

	return result
}

// extractSQLServerComponents parses a SQL Server JDBC URL and extracts protocol,
// hosts, username, password, and database name from semicolon-separated parameters.
// SQL Server uses a distinct format: jdbc:sqlserver://host:port;param=value;...
// where credentials (user=, password=) and database (databaseName=) are specified
// as semicolon-separated key=value pairs rather than in the URL path or userinfo.
func extractSQLServerComponents(rawURL string, protocol string) JDBCParsedURL {
	result := JDBCParsedURL{FullURL: rawURL, Protocol: protocol}
	result.Hosts = ExtractJDBCHosts(rawURL)

	// Strip "jdbc:" prefix (case-insensitive) from the original URL, preserving
	// case for passwords.
	origNorm := rawURL
	origNorm, _ = strings.CutPrefix(origNorm, "jdbc:")
	origNorm, _ = strings.CutPrefix(origNorm, "JDBC:")
	origParts := strings.SplitN(origNorm, "://", 2)
	origRest := ""
	if len(origParts) == 2 {
		origRest = origParts[1]
	}

	// Parse semicolon-separated parameters for credentials and database name.
	for p := range strings.SplitSeq(origRest, ";") {
		p = strings.TrimSpace(p)
		lower := strings.ToLower(p)
		if strings.HasPrefix(lower, "databasename=") {
			_, result.Database, _ = strings.Cut(p, "=")
		}
		if strings.HasPrefix(lower, "user=") {
			_, result.Username, _ = strings.Cut(p, "=")
		}
		if strings.HasPrefix(lower, "password=") {
			_, result.Password, _ = strings.Cut(p, "=")
		}
	}

	return result
}
