package rust

import (
	"bytes"
	"context"
	"io"
)

// Client is an interface for building and handling binary artifacts from a rust project
type Client interface {
	BuildSource(ctx context.Context, path string, targetDir string) ([]string, error)
	ExtractRlibArchive(rlibPath string) (bytes.Buffer, error)
	FunctionsFromDWARF(readAt io.ReaderAt) (map[string]struct{}, error)
	RustToolchainAvailable(ctx context.Context) bool
}
