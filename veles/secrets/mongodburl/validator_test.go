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

package mongodbconnectionurl_test

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/google/osv-scalibr/veles"
	mongodburi "github.com/google/osv-scalibr/veles/secrets/mongodburl"
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/modules/mongodb"
	"github.com/testcontainers/testcontainers-go/wait"
)

const (
	testMongoUser = "testuser"
	testMongoPass = "testpassword"
)

// startMongoContainer starts a MongoDB container with authentication enabled.
// It returns the container and the connection string (without credentials).
func startMongoContainer(t *testing.T) (string, string) {
	t.Helper()

	ctx := t.Context()

	mongoC, err := mongodb.Run(ctx,
		"mongo:7",
		mongodb.WithUsername(testMongoUser),
		mongodb.WithPassword(testMongoPass),
		testcontainers.WithWaitStrategy(
			wait.ForLog("Waiting for connections").WithStartupTimeout(60*time.Second),
		),
	)
	if err != nil {
		t.Fatalf("failed to start MongoDB container: %v", err)
	}

	t.Cleanup(func() {
		if err := mongoC.Terminate(ctx); err != nil {
			t.Logf("failed to terminate MongoDB container: %v", err)
		}
	})

	host, err := mongoC.Host(ctx)
	if err != nil {
		t.Fatalf("failed to get container host: %v", err)
	}

	port, err := mongoC.MappedPort(ctx, "27017")
	if err != nil {
		t.Fatalf("failed to get mapped port: %v", err)
	}

	connStr, err := mongoC.ConnectionString(ctx)
	if err != nil {
		t.Fatalf("failed to get connection string: %v", err)
	}

	return fmt.Sprintf("%s:%s", host, port.Port()), connStr
}

func TestValidator_ValidCredentials(t *testing.T) {
	hostPort, _ := startMongoContainer(t)

	validator := mongodburi.NewValidator()
	validator.ConnectTimeout = 10 * time.Second

	url := fmt.Sprintf("mongodb://%s:%s@%s/?authSource=admin", testMongoUser, testMongoPass, hostPort)
	secret := mongodburi.MongoDBConnectionURL{URL: url}

	got, err := validator.Validate(t.Context(), secret)
	if err != nil {
		t.Fatalf("Validate() unexpected error: %v", err)
	}
	if got != veles.ValidationValid {
		t.Errorf("Validate() = %v, want %v", got, veles.ValidationValid)
	}
}

func TestValidator_InvalidCredentials(t *testing.T) {
	hostPort, _ := startMongoContainer(t)

	validator := mongodburi.NewValidator()
	validator.ConnectTimeout = 10 * time.Second

	url := fmt.Sprintf("mongodb://wronguser:wrongpass@%s/?authSource=admin", hostPort)
	secret := mongodburi.MongoDBConnectionURL{URL: url}

	got, err := validator.Validate(t.Context(), secret)
	// Auth failure should return ValidationInvalid with no error.
	if err != nil {
		t.Fatalf("Validate() unexpected error: %v", err)
	}
	if got != veles.ValidationInvalid {
		t.Errorf("Validate() = %v, want %v", got, veles.ValidationInvalid)
	}
}

func TestValidator_UnreachableServer(t *testing.T) {
	validator := mongodburi.NewValidator()
	validator.ConnectTimeout = 2 * time.Second

	// Use a non-routable address to simulate an unreachable server.
	secret := mongodburi.MongoDBConnectionURL{URL: "mongodb://user:pass@192.0.2.1:27017"}

	got, err := validator.Validate(t.Context(), secret)
	if err == nil {
		t.Error("Validate() expected error for unreachable server, got nil")
	}
	if got != veles.ValidationFailed {
		t.Errorf("Validate() = %v, want %v", got, veles.ValidationFailed)
	}
}

func TestValidator_InvalidURI(t *testing.T) {
	validator := mongodburi.NewValidator()
	validator.ConnectTimeout = 2 * time.Second

	secret := mongodburi.MongoDBConnectionURL{URL: "not-a-valid-uri"}

	got, err := validator.Validate(t.Context(), secret)
	if err == nil {
		t.Error("Validate() expected error for invalid URI, got nil")
	}
	if got != veles.ValidationInvalid {
		t.Errorf("Validate() = %v, want %v", got, veles.ValidationInvalid)
	}
}

func TestValidator_ContextCancellation(t *testing.T) {
	hostPort, _ := startMongoContainer(t)

	validator := mongodburi.NewValidator()
	validator.ConnectTimeout = 10 * time.Second

	url := fmt.Sprintf("mongodb://%s:%s@%s/?authSource=admin", testMongoUser, testMongoPass, hostPort)
	secret := mongodburi.MongoDBConnectionURL{URL: url}

	ctx, cancel := context.WithCancel(t.Context())
	cancel() // Cancel immediately

	got, err := validator.Validate(ctx, secret)
	if err == nil {
		t.Error("Validate() expected error due to context cancellation, got nil")
	}
	if got != veles.ValidationFailed {
		t.Errorf("Validate() = %v, want %v", got, veles.ValidationFailed)
	}
}

func TestValidator_ConnectionStringFromContainer(t *testing.T) {
	_, connStr := startMongoContainer(t)

	validator := mongodburi.NewValidator()
	validator.ConnectTimeout = 10 * time.Second

	// The connection string from testcontainers doesn't include credentials,
	// so we need to construct one with credentials.
	secret := mongodburi.MongoDBConnectionURL{URL: connStr}

	got, err := validator.Validate(t.Context(), secret)
	if err != nil {
		t.Fatalf("Validate() unexpected error: %v", err)
	}
	// The container's connection string includes credentials, so it should be valid.
	if got != veles.ValidationValid {
		t.Errorf("Validate() = %v, want %v", got, veles.ValidationValid)
	}
}
