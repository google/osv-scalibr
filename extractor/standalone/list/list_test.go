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

package list_test

import (
	"regexp"
	"testing"

	cpb "github.com/google/osv-scalibr/binary/proto/config_go_proto"
	el "github.com/google/osv-scalibr/extractor/standalone/list"
)

var (
	reValidName = regexp.MustCompile(`^[a-z0-9/-]+$`)
)

func TestPluginNamesValid(t *testing.T) {
	for _, initers := range el.All {
		for _, initer := range initers {
			name := initer(&cpb.PluginConfig{}).Name()
			if !reValidName.MatchString(name) {
				t.Errorf("Invalid plugin name %q", name)
			}
		}
	}
}
