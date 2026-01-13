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

package fun

import "testdata/basic"

func NewPlugin() basic.MyPlugin {
	return &basic.PluginA{}
}

//nolint:plugger // This function is meant to be used only in testing as it returns the same plugin as fun.NewPlugin
func NewPluginAlias(something string) basic.MyPlugin {
	return &basic.PluginA{}
}
