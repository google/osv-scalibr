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

//go:build !linux

package containerd_test

import (
	"testing"

	plugin "github.com/google/osv-scalibr/extractor/standalone/containers/containerd"
)

func TestDummyExtract(t *testing.T) {
	dummyExtractor := plugin.New(plugin.Config{})
	_, err := dummyExtractor.Extract(t.Context(), nil)
	// Always expect an error on non-Linux.
	if err == nil {
		t.Fatalf("Extract() error: %v", err)
	}
}
