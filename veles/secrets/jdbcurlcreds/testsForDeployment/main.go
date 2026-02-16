// test the parsing logic of the JDBC URL parser for actual deployments
package main

import (
	"context"
	"fmt"

	"github.com/google/osv-scalibr/veles/secrets/jdbcurlcreds"
)

func main() {
	fmt.Println("=== JDBC URL Deployment Tests ===")
	fmt.Println("Testing against docker-compose services (localhost)")
	fmt.Println()

	// JDBC URLs matching the docker-compose.yml services.
	// Each URL exercises a distinct host/credential parsing path from detector.go.
	testURLs := []string{
		// === PostgreSQL formats ===

		// Simple userinfo: jdbc:postgresql://user:pass@host:port/db
		"jdbc:postgresql://postgres:mysecretpassword@localhost:5432/testdb",
		// Trust auth (no password): jdbc:postgresql://user@host:port/db
		"jdbc:postgresql://postgres@localhost:5433/testdb",
		// Query param credentials: jdbc:postgresql://host:port/db?user=...&password=...
		"jdbc:postgresql://localhost:5432/testdb?user=postgres&password=mysecretpassword",
		// Comma-separated multi-host: jdbc:postgresql://host1:port1,host2:port2/db
		"jdbc:postgresql://postgres:mysecretpassword@localhost:5432,localhost:5433/testdb",
		// No jdbc: prefix: postgresql://host:port/db
		"postgresql://postgres:mysecretpassword@localhost:5432/testdb",
		// IPv6 host: jdbc:postgresql://[::1]:port/db
		"jdbc:postgresql://postgres:mysecretpassword@[::1]:5432/testdb",

		// === MySQL formats ===
		// Simple userinfo: jdbc:mysql://user:pass@host:port/db
		"jdbc:mysql://username:password@localhost:3306/testdb",
		// No password: jdbc:mysql://user@host:port/db
		"jdbc:mysql://root@localhost:3307/testdb",
		// Query param credentials: jdbc:mysql://host:port/db?user=...&password=...
		"jdbc:mysql://localhost:3306/testdb?user=username&password=password",
		// MySQL address syntax: jdbc:mysql://address=(host=...)(port=...)/db
		// Uses port 3307 (mysql-noauth, allows empty password with root)
		"jdbc:mysql://address=(host=localhost)(port=3307)/testdb",
		// MySQL parenthesized key-value: jdbc:mysql://(host=...,port=...,key=val)/db
		// Uses port 3307 (mysql-noauth, allows empty password with root)
		"jdbc:mysql://(host=localhost,port=3307)/testdb",
		// MySQL bracket syntax: jdbc:mysql://user:pass@[host1:port1,host2:port2]/db
		"jdbc:mysql://username:password@[localhost:3306,localhost:3307]/testdb",
		// MySQL bracket + address syntax: jdbc:mysql://user:pass@[address=(host=...)(port=...),...]/db
		"jdbc:mysql://username:password@[address=(host=localhost)(port=3306),address=(host=localhost)(port=3307)]/testdb",
		// Mixed plain and parenthesized: jdbc:mysql://host1:port1,(host=host2,port=port2)/db
		// Uses root with empty password; port 3307 (mysql-noauth) accepts root without password
		"jdbc:mysql://root:@localhost:3306,(host=localhost,port=3307)/testdb",
		// mysql+srv scheme: jdbc:mysql+srv://host:port/db
		"jdbc:mysql+srv://username:password@localhost:3306/testdb",
		// mysql+srv with sub-protocol: jdbc:mysql+srv:replication://host:port/db
		"jdbc:mysql+srv:replication://username:password@localhost:3306/testdb",
		// No jdbc: prefix: mysql+srv://host:port/db
		"mysql+srv://username:password@localhost:3306/testdb",
		// mysqlx scheme: mysqlx://host:port/db
		"mysqlx://username:password@localhost:3306/testdb",

		// === SQL Server formats ===

		// Semicolon params with databaseName: jdbc:sqlserver://host:port;databaseName=...;user=...;password=...
		"jdbc:sqlserver://localhost:1433;databaseName=master;user=sa;password=YourStr0ngP@ss;encrypt=true;trustServerCertificate=true;",
		// SQL Server without port (default): jdbc:sqlserver://host;user=...;password=...
		"jdbc:sqlserver://localhost;user=sa;password=YourStr0ngP@ss;encrypt=true;trustServerCertificate=true;",
	}

	validator := jdbcurlcreds.NewValidator()
	ctx := context.Background()

	for i, jdbcURL := range testURLs {
		fmt.Printf("--- Test %d ---\n", i+1)
		fmt.Printf("  URL:      %s\n", jdbcURL)

		parsed, err := jdbcurlcreds.ExtractJDBCComponents(jdbcURL)
		if err != nil {
			fmt.Printf("  [WARN] %v\n", err)
			continue
		}

		fmt.Printf("  Protocol: %s\n", parsed.Protocol)
		if len(parsed.Hosts) > 0 {
			for j, h := range parsed.Hosts {
				port := h.Port
				if port == "" {
					port = "(default)"
				}
				fmt.Printf("  Host[%d]:  %s:%s\n", j, h.Host, port)
				fmt.Printf("  IsLocal:  %v\n", jdbcurlcreds.IsLocalHost(h.Host))
			}
		} else {
			fmt.Println("  Host:     (none detected)")
		}
		fmt.Printf("  Username: %s\n", parsed.Username)
		fmt.Printf("  Password: %s\n", parsed.Password)
		fmt.Printf("  Database: %s\n", parsed.Database)

		// Validate by attempting to connect using the Validator.
		secret := jdbcurlcreds.Credentials{FullURL: jdbcURL}
		status, err := validator.Validate(ctx, secret)
		if err != nil {
			fmt.Printf("  Connect:  FAILED - %v\n", err)
		} else {
			fmt.Printf("  Connect:  %v\n", status)
		}
		fmt.Println()
	}
}
