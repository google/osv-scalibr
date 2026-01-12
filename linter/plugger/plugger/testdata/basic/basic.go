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

// Package basic is a basic test package for the linter
package basic

// MyPlugin is the interface whose usage is being tested
type MyPlugin interface {
	Run()
}

// NotAPlugin is an interface not implementing MyPlugin
type NotAPlugin interface {
	SomethingElse()
}

// PluginA is a struct implementing MyPlugin
type PluginA struct{}

// Run implements the MyPlugin interface
func (p *PluginA) Run() {}

// PluginB is another struct implementing MyPlugin
type PluginB struct{}

// Run implements the MyPlugin interface
func (p *PluginB) Run() {}

// NewPluginA creates a new PluginA
func NewPluginA() MyPlugin { return &PluginA{} }

// NewPluginB creates a new PluginB
func NewPluginB() MyPlugin { return &PluginB{} }
