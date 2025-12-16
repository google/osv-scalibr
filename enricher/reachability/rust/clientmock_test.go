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
	extractedRlibBuffer bytes.Buffer
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
func (c *mockClient) ExtractRlibArchive(_ string) (bytes.Buffer, error) {
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
