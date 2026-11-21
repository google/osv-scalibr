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
	"debug/elf"
	"debug/gosym"
	"encoding/binary"
	"errors"
	"io"
	"iter"
	"net/url"
	"strings"

	"github.com/google/osv-scalibr/log"
)

// ModuleEdge represents a dependency between two modules in a Go binary.
type ModuleEdge struct {
	Module    string
	DependsOn string
}

// ExtractDependencyGraph extracts the inter-module dependency graph from a Go binary.
func ExtractDependencyGraph(r io.ReaderAt, bi *buildinfo.BuildInfo) ([]ModuleEdge, error) {
	if bi == nil {
		return nil, nil
	}

	sections, err := loadMetadataSectionsFromELF(r)
	if err != nil || sections == nil {
		return nil, err
	}

	mainModPath := "main"
	if bi.Main.Path != "" {
		mainModPath = bi.Main.Path
	}

	functions := mapFunctionsToModules(sections.symTable.Funcs, bi, mainModPath)
	return sections.scanCrossModuleCalls(functions), nil
}

type sections struct {
	symTable  *gosym.Table
	textStart uint64
	textData  []byte
	scanner   callScanner
}

func loadMetadataSectionsFromELF(r io.ReaderAt) (*sections, error) {
	ef, err := elf.NewFile(r)
	if err != nil {
		return nil, err
	}
	defer ef.Close()

	textSec := ef.Section(".text")
	if textSec == nil {
		return nil, errors.New("missing .text")
	}
	textData, err := textSec.Data()
	if err != nil {
		return nil, err
	}

	scanner := scannerForArch(ef.Machine)
	if scanner == nil {
		log.Warnf("%v is unsupported for dependency relations extraction", ef.Machine)
		return nil, nil
	}

	pclnSec := findPclntab(ef)
	if pclnSec == nil {
		return nil, errors.New("missing .gopclntab")
	}
	pclnData, err := pclnSec.Data()
	if err != nil {
		return nil, err
	}

	lineTable := gosym.NewLineTable(pclnData, textSec.Addr)
	symTable, err := gosym.NewTable(nil, lineTable)
	if err != nil {
		return nil, err
	}

	return &sections{
		symTable:  symTable,
		textStart: textSec.Addr,
		textData:  textData,
		scanner:   scanner,
	}, nil
}

func findPclntab(ef *elf.File) *elf.Section {
	for _, sec := range ef.Sections {
		if strings.Contains(sec.Name, "gopclntab") {
			return sec
		}
	}
	return nil
}

func (s *sections) scanCrossModuleCalls(functions *moduleFunctionIndex) []ModuleEdge {
	textLen := uint64(len(s.textData))
	seen := make(map[ModuleEdge]bool)
	var edges []ModuleEdge
	for _, fr := range functions.funcRanges {
		if fr.entry < s.textStart || fr.end > s.textStart+textLen {
			continue
		}
		body := s.textData[fr.entry-s.textStart : fr.end-s.textStart]
		for targetPC := range s.scanner.ScanCalls(body, fr.entry) {
			if dstMod, ok := functions.entryToModule[targetPC]; ok && dstMod != fr.mod {
				edge := ModuleEdge{Module: fr.mod, DependsOn: dstMod}
				if !seen[edge] {
					seen[edge] = true
					edges = append(edges, edge)
				}
			}
		}
	}
	return edges
}

type moduleFunctionIndex struct {
	entryToModule map[uint64]string
	funcRanges    []funcRange
}

type funcRange struct {
	entry uint64
	end   uint64
	mod   string
}

func mapFunctionsToModules(funcs []gosym.Func, bi *buildinfo.BuildInfo, mainModPath string) *moduleFunctionIndex {
	entryToModule := make(map[uint64]string, len(funcs))
	var funcRanges []funcRange

	for _, f := range funcs {
		if f.Func == nil || f.End <= f.Entry {
			continue
		}
		pkg := extractPackage(f.Name)
		mod := resolvePackageModule(pkg, bi, mainModPath)
		if mod == "" {
			continue
		}
		entryToModule[f.Entry] = mod
		funcRanges = append(funcRanges, funcRange{
			entry: f.Entry,
			end:   f.End,
			mod:   mod,
		})
	}
	return &moduleFunctionIndex{
		entryToModule: entryToModule,
		funcRanges:    funcRanges,
	}
}

func extractPackage(sym string) string {
	slash := strings.LastIndex(sym, "/")
	var pkg string
	if slash < 0 {
		p, _, _ := strings.Cut(sym, ".")
		pkg = p
	} else {
		p, _, _ := strings.Cut(sym[slash+1:], ".")
		pkg = sym[:slash+1] + p
	}
	if unescaped, err := url.PathUnescape(pkg); err == nil {
		return unescaped
	}
	return pkg
}

func resolvePackageModule(pkg string, bi *buildinfo.BuildInfo, mainModPath string) string {
	if pkg == "" || pkg == "main" {
		return mainModPath
	}

	var bestMod string
	var bestLen int

	if mainModPath != "main" && hasPackagePrefix(pkg, mainModPath) {
		bestMod, bestLen = mainModPath, len(mainModPath)
	}

	for _, dep := range bi.Deps {
		target := dep.Path
		if dep.Replace != nil && dep.Replace.Path != "" {
			target = dep.Replace.Path
			if hasPackagePrefix(pkg, dep.Replace.Path) && len(dep.Replace.Path) > bestLen {
				bestMod, bestLen = target, len(dep.Replace.Path)
			}
		}
		if hasPackagePrefix(pkg, dep.Path) && len(dep.Path) > bestLen {
			bestMod, bestLen = target, len(dep.Path)
		}
	}

	return bestMod
}

func hasPackagePrefix(pkg, prefix string) bool {
	return pkg == prefix || strings.HasPrefix(pkg, prefix+"/")
}

type callScanner interface {
	ScanCalls(body []byte, entry uint64) iter.Seq[uint64]
}

func scannerForArch(m elf.Machine) callScanner {
	switch m {
	case elf.EM_X86_64:
		return x86_64CallScanner{}
	default:
		return nil
	}
}

type x86_64CallScanner struct{}

func (s x86_64CallScanner) ScanCalls(body []byte, entry uint64) iter.Seq[uint64] {
	return func(yield func(uint64) bool) {
		for i := 0; i+5 <= len(body); i++ {
			if b := body[i]; b == 0xE8 || b == 0xE9 { // 0xE8 = CALL rel32, 0xE9 = JMP rel32 (tail call)
				rel := int32(binary.LittleEndian.Uint32(body[i+1 : i+5]))
				targetPC := entry + uint64(i) + 5 + uint64(int64(rel))
				if !yield(targetPC) {
					return
				}
			}
		}
	}
}
