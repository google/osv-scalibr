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

package mongodbconnectionurl

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/google/osv-scalibr/veles"
	"go.mongodb.org/mongo-driver/v2/mongo"
	"go.mongodb.org/mongo-driver/v2/mongo/options"
)

// Validator validates MongoDB connection URLs by attempting to connect
// and ping the MongoDB server.
type Validator struct {
	// ConnectTimeout is the maximum time to wait for a connection.
	// Defaults to 5 seconds if zero.
	ConnectTimeout time.Duration
}

// NewValidator creates a new Validator for MongoDB connection URLs.
func NewValidator() *Validator {
	return &Validator{
		ConnectTimeout: 5 * time.Second,
	}
}

// Validate attempts to connect to the MongoDB server using the provided
// connection URL and sends a ping command. If the ping succeeds, the
// credentials are considered valid. Authentication failures indicate
// invalid credentials. Other errors result in ValidationFailed.
func (v *Validator) Validate(ctx context.Context, secret MongoDBConnectionURL) (veles.ValidationStatus, error) {
	timeout := v.ConnectTimeout
	if timeout == 0 {
		timeout = 5 * time.Second
	}

	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	clientOpts := options.Client().
		ApplyURI(secret.URL).
		SetConnectTimeout(timeout).
		SetServerSelectionTimeout(timeout)

	client, err := mongo.Connect(clientOpts)
	if err != nil {
		// URI parse errors or config errors mean the URL is malformed/invalid.
		return veles.ValidationInvalid, fmt.Errorf("mongo.Connect: %w", err)
	}
	defer func() {
		_ = client.Disconnect(context.Background())
	}()

	err = client.Ping(ctx, nil)
	if err != nil {
		if isAuthError(err) {
			return veles.ValidationInvalid, nil
		}
		return veles.ValidationFailed, fmt.Errorf("ping: %w", err)
	}

	return veles.ValidationValid, nil
}

// isAuthError checks whether the error indicates an authentication failure.
func isAuthError(err error) bool {
	if err == nil {
		return false
	}
	errMsg := err.Error()
	// MongoDB authentication error codes: 18 (AuthenticationFailed)
	// The driver may return errors containing these strings.
	return strings.Contains(errMsg, "authentication failed") ||
		strings.Contains(errMsg, "Authentication failed") ||
		strings.Contains(errMsg, "auth error") ||
		strings.Contains(errMsg, "(Unauthorized)") ||
		strings.Contains(errMsg, "not authorized")
}
