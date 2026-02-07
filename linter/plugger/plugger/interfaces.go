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

package plugger

import (
	"go/types"
	"slices"
	"sync"

	"golang.org/x/tools/go/packages"
)

// FindInterfaces returns all interfaces that follow the specified pattern
func FindInterfaces(pkgs []*packages.Package, interfaceNames []string) []*types.Named {
	result := []*types.Named{}

	var mu sync.Mutex
	var wg sync.WaitGroup

	for _, pkg := range pkgs {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for ident, obj := range pkg.TypesInfo.Defs {
				if obj == nil {
					continue
				}
				named, ok := obj.Type().(*types.Named)
				if !ok {
					continue
				}

				if _, ok := named.Underlying().(*types.Interface); !ok {
					continue
				}
				if !slices.Contains(interfaceNames, pkg.String()+"."+ident.Name) {
					continue
				}
				mu.Lock()
				result = append(result, named)
				mu.Unlock()
			}
		}()
	}
	wg.Wait()
	return result
}
