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

package rust_test

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"os"
)

// mockClient is the mock implementation of Client for testing purpose
type mockClient struct {
	binaryPaths         []string
	extractedRlibBuffer *bytes.Buffer
	funcSymbols         map[string]struct{}
	rustAvailable       bool
}

func newMockClient(binaryPathsFile, extractedSymbolsFile string, rustAvailable bool) (*mockClient, error) {
	// Read binary paths
	binData, err := os.ReadFile(binaryPathsFile)
	if err != nil {
		return nil, err
	}
	var binaryPaths []string
	if err := json.Unmarshal(binData, &binaryPaths); err != nil {
		return nil, err
	}

	// Read extracted symbols
	symData, err := os.ReadFile(extractedSymbolsFile)
	if err != nil {
		return nil, err
	}
	var syms []string
	if err := json.Unmarshal(symData, &syms); err != nil {
		return nil, err
	}

	funcSymbols := make(map[string]struct{})
	for _, s := range syms {
		funcSymbols[s] = struct{}{}
	}

	return &mockClient{
		binaryPaths:   binaryPaths,
		funcSymbols:   funcSymbols,
		rustAvailable: rustAvailable,
	}, nil
}

// BuildSource mocks building a rust project and returns a predefined list of binary paths
func (c *mockClient) BuildSource(_ context.Context, _ string, _ string) ([]string, error) {
	return c.binaryPaths, nil
}

// ExtractRlibArchive mocks the file path to a temporary ELF Object file extracted from the given rlib.
func (c *mockClient) ExtractRlibArchive(_ string) (*bytes.Buffer, error) {
	return c.extractedRlibBuffer, nil
}

// FunctionsFromDWARF returns function symbols from predefined list
func (c *mockClient) FunctionsFromDWARF(_ io.ReaderAt) (map[string]struct{}, error) {
	return c.funcSymbols, nil
}

// RustToolchainAvailable checks if the rust toolchain is available
func (c *mockClient) RustToolchainAvailable(_ context.Context) bool {
	return c.rustAvailable
}
