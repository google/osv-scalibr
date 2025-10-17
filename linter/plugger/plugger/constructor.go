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
}

// Returns returns true if the function returns the given type
func (f *Function) Returns(t *types.Named) bool {
	for _, r := range f.ReturnTypes {
		if types.Identical(r, t) || types.Identical(r, types.NewPointer(t)) {
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

// NewConstructor returns a constructor given a function and a type
func NewConstructor(f *Function, t *types.Named) *Constructor {
	return &Constructor{
		Function: f,
		Impl:     t,
	}
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
