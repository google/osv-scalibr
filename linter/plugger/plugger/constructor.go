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
	"fmt"
	"go/ast"
	"go/types"
	"path/filepath"

	"golang.org/x/tools/go/packages"
)

// Function is a generic function
type Function struct {
	Fun         *ast.FuncDecl
	Pkg         *packages.Package
	ReturnTypes []types.Type
	Aliases     []*Function
}

func (f Function) String() string {
	return f.Pkg.Name + "." + f.Fun.Name.Name
}

// Returns returns true if the function returns the given type
func (f *Function) Returns(t *types.Named) bool {
	for _, r := range f.ReturnTypes {
		// direct or pointer match
		if types.Identical(r, t) || types.Identical(r, types.NewPointer(t)) {
			return true
		}

		// check if the functions returns an interface of the type
		if doesImplement(r, t) || doesImplement(types.NewPointer(r), t) {
			return true
		}
	}
	return false
}

// Constructor is a function with an assigned register type
type Constructor struct {
	*Function

	registers *types.Named
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

// Registers returns the type of the plugin which the construct registers.
func (c Constructor) Registers() string {
	obj := c.registers.Obj()
	return obj.Pkg().Name() + "." + obj.Name()
}
