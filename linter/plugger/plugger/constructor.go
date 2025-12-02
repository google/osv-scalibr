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

package plugger

import (
	"fmt"
	"go/ast"
	"go/types"
	"path/filepath"

	"golang.org/x/tools/go/packages"
)

// Function is a generic function
type Function struct {
	Fun         *ast.FuncDecl
	Aliases     []*Function
	Pkg         *packages.Package
	ReturnTypes []types.Type
}

func (f Function) String() string {
	return f.Fun.Name.Name
}

// Returns returns true if the function returns the given type
func (f *Function) Returns(t *types.Named) bool {
	for _, r := range f.ReturnTypes {
		// direct or pointer match
		if types.Identical(r, t) || types.Identical(r, types.NewPointer(t)) {
			return true
		}

		// unwrap pointer once (if any)
		elem := r
		if p, ok := r.(*types.Pointer); ok {
			elem = p.Elem()
		}

		// generic named match
		if named, ok := elem.(*types.Named); ok && named.Origin() == t {
			return true
		}
	}
	return false
}

// Constructor is a function with an assigned type
type Constructor struct {
	*Function

	Impl *types.Named
}

// Pos returns a compiler style position of the constructor
func (c Constructor) Pos(cwd string) (string, error) {
	pos := c.Pkg.Fset.Position(c.Fun.Pos())
	rel, err := filepath.Rel(cwd, pos.Filename)
	if err != nil {
		return "", err
	}

	return fmt.Sprintf("%s:%d:%d", rel, pos.Line, pos.Column), nil
}
