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

package gobinary

import (
	"debug/buildinfo"
	"debug/gosym"
	"runtime/debug"
	"testing"

	"github.com/google/go-cmp/cmp"
)

func TestResolvePackageModule(t *testing.T) {
	bi := &buildinfo.BuildInfo{
		Main: debug.Module{
			Path: "example.com/mainmod",
		},
		Deps: []*debug.Module{{
			Path:    "example.com/dep1",
			Version: "v1.0.0",
		}, {
			Path:    "example.com/replaced",
			Version: "v1.0.0",
			Replace: &debug.Module{
				Path:    "example.com/replacement",
				Version: "v1.0.0",
			},
		}, {
			Path:    "internalmod",
			Version: "v1.0.0",
		}, {
			Path:    "example.com/dep.v2",
			Version: "v2.0.0",
		}, {
			Path:    "example.com/telemetry",
			Version: "v1.0.0",
		}},
	}

	tests := []struct {
		name        string
		pkg         string
		mainModPath string
		want        string
	}{{
		name:        "empty package maps to main",
		pkg:         "",
		mainModPath: "example.com/mainmod",
		want:        "example.com/mainmod",
	}, {
		name:        "main package maps to main",
		pkg:         "main",
		mainModPath: "example.com/mainmod",
		want:        "example.com/mainmod",
	}, {
		name:        "main subpackage without domain dot resolves to main module",
		pkg:         "example.com/mainmod/internal/subpkg",
		mainModPath: "example.com/mainmod",
		want:        "example.com/mainmod",
	}, {
		name:        "dependency subpackage resolves to dependency module",
		pkg:         "example.com/dep1/subpkg",
		mainModPath: "example.com/mainmod",
		want:        "example.com/dep1",
	}, {
		name:        "dependency without domain dot resolves to dependency module",
		pkg:         "internalmod/subpkg",
		mainModPath: "example.com/mainmod",
		want:        "internalmod",
	}, {
		name:        "replaced module resolves to replacement target name",
		pkg:         "example.com/replaced",
		mainModPath: "example.com/mainmod",
		want:        "example.com/replacement",
	}, {
		name:        "replaced module subpackage resolves to replacement target name",
		pkg:         "example.com/replaced/internal",
		mainModPath: "example.com/mainmod",
		want:        "example.com/replacement",
	}, {
		name:        "replacement module path itself resolves to replacement target name",
		pkg:         "example.com/replacement/internal",
		mainModPath: "example.com/mainmod",
		want:        "example.com/replacement",
	}, {
		name:        "dependency module with dot in version resolves to dependency module",
		pkg:         "example.com/dep.v2",
		mainModPath: "example.com/mainmod",
		want:        "example.com/dep.v2",
	}, {
		name:        "subpackage with dot in version resolves to dependency module",
		pkg:         "example.com/telemetry/subpkg/v1.20.0",
		mainModPath: "example.com/mainmod",
		want:        "example.com/telemetry",
	}, {
		name:        "standard library package resolves to empty string",
		pkg:         "fmt",
		mainModPath: "example.com/mainmod",
		want:        "",
	}, {
		name:        "standard library multi-segment package resolves to empty string",
		pkg:         "net/http",
		mainModPath: "example.com/mainmod",
		want:        "",
	}, {
		name:        "runtime type symbol resolves to empty string",
		pkg:         "type:.eq.fmt.wrapError",
		mainModPath: "example.com/mainmod",
		want:        "",
	}, {
		name:        "untracked third-party package resolves to empty string",
		pkg:         "example.com/untracked/sub/pkg",
		mainModPath: "example.com/mainmod",
		want:        "",
	}}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := resolvePackageModule(tt.pkg, bi, tt.mainModPath)
			if got != tt.want {
				t.Errorf("resolvePackageModule(%q) = %q, want %q", tt.pkg, got, tt.want)
			}
		})
	}
}

func TestExtractPackage(t *testing.T) {
	tests := []struct {
		sym  string
		want string
	}{{
		sym:  "example.com/dep%2ev2.Unmarshal",
		want: "example.com/dep.v2",
	}, {
		sym:  "example.com/dep%2ev2.(*decoder).unmarshal",
		want: "example.com/dep.v2",
	}, {
		sym:  "example.com/telemetry/subpkg/v1%2e20%2e0.Attributes",
		want: "example.com/telemetry/subpkg/v1.20.0",
	}, {
		sym:  "example.com/dep1/subpkg.Foo",
		want: "example.com/dep1/subpkg",
	}, {
		sym:  "fmt.Println",
		want: "fmt",
	}, {
		sym:  "main.main",
		want: "main",
	}}

	for _, tt := range tests {
		t.Run(tt.sym, func(t *testing.T) {
			got := extractPackage(tt.sym)
			if got != tt.want {
				t.Errorf("extractPackage(%q) = %q, want %q", tt.sym, got, tt.want)
			}
		})
	}
}

func TestX86_64CallScanner(t *testing.T) {
	scanner := x86_64CallScanner{}

	tests := []struct {
		name      string
		body      []byte
		entry     uint64
		wantCalls []uint64
	}{{
		name: "direct call 0xE8",
		// Entry: 0x400000. Instruction at i=0: CALL rel32 (nextPC = 0x400005).
		// Want target: 0x401000. Rel = 0x401000 - 0x400005 = 0xFFB.
		body:      []byte{0xE8, 0xFB, 0x0F, 0x00, 0x00},
		entry:     0x400000,
		wantCalls: []uint64{0x401000},
	}, {
		name: "tail call 0xE9",
		// Entry: 0x400000. Instruction at i=0: JMP rel32 (nextPC = 0x400005).
		// Want target: 0x402000. Rel = 0x402000 - 0x400005 = 0x1FFB.
		body:      []byte{0xE9, 0xFB, 0x1F, 0x00, 0x00},
		entry:     0x400000,
		wantCalls: []uint64{0x402000},
	}, {
		name:      "no calls",
		body:      []byte{0x90, 0x90, 0xC3},
		entry:     0x400000,
		wantCalls: nil,
	}}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var got []uint64
			for targetPC := range scanner.ScanCalls(tt.body, tt.entry) {
				got = append(got, targetPC)
			}
			if diff := cmp.Diff(tt.wantCalls, got); diff != "" {
				t.Errorf("ScanCalls mismatch (-want +got):\n%s", diff)
			}
		})
	}
}

func TestMapFunctionsToModules(t *testing.T) {
	bi := &buildinfo.BuildInfo{
		Main: debug.Module{Path: "example.com/mainmod"},
		Deps: []*debug.Module{
			{Path: "example.com/dep1"},
		},
	}

	validFunc := &gosym.Func{Entry: 0x402000, End: 0x402100}
	validSym := &gosym.Sym{Name: "example.com/dep1.Foo", Func: validFunc}
	validFunc.Sym = validSym

	funcs := []gosym.Func{
		// f.Func == nil (exercises graph.go line 142)
		{
			Sym:   &gosym.Sym{Name: "example.com/dep1.NoFunc", Func: nil},
			Entry: 0x401000,
			End:   0x401100,
		},
		// f.End <= f.Entry (exercises graph.go line 142)
		{
			Sym:   &gosym.Sym{Name: "example.com/dep1.ZeroLength"},
			Entry: 0x401500,
			End:   0x401500,
		},
		// valid function
		*validFunc,
	}

	idx := mapFunctionsToModules(funcs, bi, "example.com/mainmod")
	if len(idx.entryToModule) != 1 || idx.entryToModule[0x402000] != "example.com/dep1" {
		t.Errorf("Unexpected function index: %v", idx.entryToModule)
	}
}

func TestScanCrossModuleCalls(t *testing.T) {
	sec := &sections{
		textStart: 0x401000,
		textData:  make([]byte, 0x1000),
		scanner:   x86_64CallScanner{},
	}

	fBefore := &gosym.Func{Entry: 0x400000, End: 0x400500}
	fBefore.Sym = &gosym.Sym{Name: "example.com/mainmod.Before", Func: fBefore}

	fAfter := &gosym.Func{Entry: 0x401500, End: 0x403000}
	fAfter.Sym = &gosym.Sym{Name: "example.com/mainmod.After", Func: fAfter}

	funcs := []gosym.Func{*fBefore, *fAfter}

	bi := &buildinfo.BuildInfo{
		Main: debug.Module{Path: "example.com/mainmod"},
	}
	idx := mapFunctionsToModules(funcs, bi, "example.com/mainmod")
	edges := sec.scanCrossModuleCalls(idx)
	if len(edges) != 0 {
		t.Errorf("Expected 0 edges for out of bounds functions, got %v", edges)
	}
}
