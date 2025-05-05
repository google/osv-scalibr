// Copyright 2025 Google LLC
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

// Package grpcclient provides a GRPC client for the deps.dev API.
package grpcclient

import (
	"crypto/x509"
	"errors"
	"fmt"
	"log"

	pb "deps.dev/api/v3alpha"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
)

const (
	address = "api.deps.dev:443"
)

var (
	// ErrMalformedConfig is returned when the config is malformed.
	ErrMalformedConfig = errors.New("malformed config")
)

// Config is the configuration for the deps.dev client.
type Config struct {
	Address string
}

// DefaultConfig returns the default configuration for the deps.dev client.
func DefaultConfig() *Config {
	return &Config{
		Address: address,
	}
}

// New returns a new deps.dev client.
func New(cfg *Config) (pb.InsightsClient, error) {
	if cfg == nil {
		return nil, fmt.Errorf("config is nil: %w", ErrMalformedConfig)
	}
	if cfg.Address == "" {
		return nil, fmt.Errorf("address is empty: %w", ErrMalformedConfig)
	}

	certPool, err := x509.SystemCertPool()
	if err != nil {
		log.Fatalf("Getting system cert pool: %v", err)
	}
	creds := credentials.NewClientTLSFromCert(certPool, "")

	conn, err := grpc.NewClient(cfg.Address, grpc.WithTransportCredentials(creds))
	if err != nil {
		return nil, err
	}

	client := pb.NewInsightsClient(conn)
	return client, nil
}
