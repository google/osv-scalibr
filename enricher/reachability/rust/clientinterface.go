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

package rust

import (
	"bytes"
	"context"
	"io"
)

// Client is an interface for building and handling binary artifacts from a rust project
type Client interface {
	BuildSource(ctx context.Context, path string, targetDir string) ([]string, error)
	ExtractRlibArchive(rlibPath string) (*bytes.Buffer, error)
	FunctionsFromDWARF(readAt io.ReaderAt) (map[string]struct{}, error)
	RustToolchainAvailable(ctx context.Context) bool
}
