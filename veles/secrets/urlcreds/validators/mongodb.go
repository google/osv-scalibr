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

package validators

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"strings"
	"time"

	"github.com/google/osv-scalibr/veles"
	"go.mongodb.org/mongo-driver/v2/mongo"
	"go.mongodb.org/mongo-driver/v2/mongo/options"
)

// MongoDBValidator validates MongoDB URL credentials.
type MongoDBValidator struct{}

// Validate attempts to connect and authenticate to a MongoDB server.
func (m *MongoDBValidator) Validate(ctx context.Context, u *url.URL) (veles.ValidationStatus, error) {
	timeout := 10 * time.Second
	opts := options.Client().
		ApplyURI(u.String()).
		SetConnectTimeout(timeout).
		SetServerSelectionTimeout(timeout)

	client, err := mongo.Connect(opts)
	if err != nil {
		return veles.ValidationFailed, fmt.Errorf("error creating MongoDB client: %w", err)
	}
	defer func() { _ = client.Disconnect(ctx) }()

	if err := client.Ping(ctx, nil); err != nil {
		if isMongoAuthError(err) {
			return veles.ValidationInvalid, nil
		}
		return veles.ValidationFailed, err
	}

	return veles.ValidationValid, nil
}

// isMongoAuthError checks if the error is a MongoDB authentication failure (code 18).
func isMongoAuthError(err error) bool {
	var cmdErr mongo.CommandError
	if errors.As(err, &cmdErr) && cmdErr.Code == 18 {
		return true
	}
	// Some driver versions wrap auth errors differently during handshake.
	return strings.Contains(err.Error(), "AuthenticationFailed")
}
