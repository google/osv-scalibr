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

package model

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/google/osv-scalibr/guidedremediation/internal/manifest/npm"
	"github.com/google/osv-scalibr/guidedremediation/internal/parser"
	"github.com/google/osv-scalibr/guidedremediation/internal/remediation"
	"github.com/google/osv-scalibr/guidedremediation/options"
)

func TestStateRelockResult_Write_Npm_IgnoreScripts(t *testing.T) {
	tmpDir := t.TempDir()

	// Mock execCommandContext
	var savedArgs []string
	oldExecCommandContext := execCommandContext
	execCommandContext = func(ctx context.Context, name string, args ...string) *exec.Cmd {
		savedArgs = append(savedArgs, args...)
		if runtime.GOOS == "windows" {
			return exec.CommandContext(ctx, "cmd", "/c", "exit 0")
		}
		return exec.CommandContext(ctx, "true")
	}
	defer func() { execCommandContext = oldExecCommandContext }()
	oldExecLookPath := execLookPath
	execLookPath = func(file string) (string, error) {
		return "/fake/path/to/" + file, nil
	}
	defer func() { execLookPath = oldExecLookPath }()

	// Mock npm executable path
	fakeNpm := filepath.Join(tmpDir, "npm")
	if err := os.WriteFile(fakeNpm, []byte("#!/bin/sh\nexit 0\n"), 0755); err != nil {
		t.Fatalf("Failed to create fake npm: %v", err)
	}
	fakeNpmCmd := filepath.Join(tmpDir, "npm.cmd")
	if err := os.WriteFile(fakeNpmCmd, []byte("@echo off\r\nexit 0\r\n"), 0755); err != nil {
		t.Fatalf("Failed to create fake npm.cmd: %v", err)
	}

	oldPath := os.Getenv("PATH")
	t.Setenv("PATH", tmpDir+string(os.PathListSeparator)+oldPath)

	manifestPath := filepath.Join(tmpDir, "package.json")
	if err := os.WriteFile(manifestPath, []byte("{}"), 0644); err != nil {
		t.Fatalf("Failed to write package.json: %v", err)
	}

	manifestRW, err := npm.GetReadWriter()
	if err != nil {
		t.Fatalf("Failed to get npm readwriter: %v", err)
	}
	manif, err := parser.ParseManifest(manifestPath, manifestRW)
	if err != nil {
		t.Fatalf("Failed to parse manifest: %v", err)
	}

	m := Model{
		options: options.FixVulnsOptions{
			Manifest: manifestPath,
			Lockfile: filepath.Join(tmpDir, "package-lock.json"),
		},
		manifestRW: manifestRW,
		relockBaseManifest: &remediation.ResolvedManifest{
			Manifest: manif,
		},
	}

	st := stateRelockResult{
		currRes: &remediation.ResolvedManifest{
			Manifest: manif,
		},
	}
	msg := st.write(m)
	if e, ok := msg.(error); ok && e != nil {
		t.Fatalf("write failed with error: %v", e)
	}
	if wmsg, ok := msg.(writeMsg); ok && wmsg.err != nil {
		t.Fatalf("write failed with writeMsg error: %v", wmsg.err)
	}

	argsStr := strings.Join(savedArgs, " ")
	if !strings.Contains(argsStr, "--ignore-scripts") {
		t.Errorf("Expected npm install to have --ignore-scripts, but got args: %s", argsStr)
	}
}
