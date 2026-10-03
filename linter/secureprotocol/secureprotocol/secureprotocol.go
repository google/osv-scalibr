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

// Package secureprotocol defines an analyzer that requires HTTPS for hardcoded
// URLs at credential-bearing HTTP request sinks.
package secureprotocol

import (
	"go/ast"
	"go/constant"
	"go/types"
	"net/url"
	"path/filepath"
	"strings"

	"golang.org/x/tools/go/analysis"
)

const simplevalidatePackage = "github.com/google/osv-scalibr/veles/secrets/common/simplevalidate"
const velesSecretsPrefix = "github.com/google/osv-scalibr/veles/secrets/"

// Analyzer rejects compile-time-constant non-HTTPS URLs used by Veles HTTP validators.
var Analyzer = &analysis.Analyzer{
	Name: "secureprotocol",
	Doc:  "require HTTPS for hardcoded URLs used by secret HTTP validators",
	Run:  run,
}

func run(pass *analysis.Pass) (any, error) {
	for _, file := range pass.Files {
		if strings.HasSuffix(filepath.Base(pass.Fset.Position(file.Pos()).Filename), "_test.go") {
			continue
		}
		ast.Inspect(file, func(node ast.Node) bool {
			switch expr := node.(type) {
			case *ast.CompositeLit:
				checkValidatorLiteral(pass, expr)
			case *ast.CallExpr:
				checkHTTPRequest(pass, expr)
			}
			return true
		})
	}
	return nil, nil
}

func checkValidatorLiteral(pass *analysis.Pass, literal *ast.CompositeLit) {
	if !isSimpleValidator(pass.TypesInfo.TypeOf(literal)) {
		return
	}
	for _, element := range literal.Elts {
		field, ok := element.(*ast.KeyValueExpr)
		if !ok {
			continue
		}
		name, ok := field.Key.(*ast.Ident)
		if !ok {
			continue
		}
		switch name.Name {
		case "Endpoint":
			checkURL(pass, field.Value)
		case "Endpoints":
			values, ok := field.Value.(*ast.CompositeLit)
			if !ok {
				continue
			}
			for _, value := range values.Elts {
				checkURL(pass, value)
			}
		}
	}
}

func isSimpleValidator(t types.Type) bool {
	if pointer, ok := t.(*types.Pointer); ok {
		t = pointer.Elem()
	}
	named, ok := t.(*types.Named)
	if !ok {
		return false
	}
	obj := named.Origin().Obj()
	return obj.Pkg() != nil && obj.Pkg().Path() == simplevalidatePackage && obj.Name() == "Validator"
}

func checkHTTPRequest(pass *analysis.Pass, call *ast.CallExpr) {
	if !strings.HasPrefix(pass.Pkg.Path(), velesSecretsPrefix) {
		return
	}
	function := calledFunction(pass, call)
	if function == nil || function.Pkg() == nil || function.Pkg().Path() != "net/http" {
		return
	}
	var urlArg int
	switch function.Name() {
	case "NewRequest":
		urlArg = 1
	case "NewRequestWithContext":
		urlArg = 2
	default:
		return
	}
	if len(call.Args) > urlArg {
		checkURL(pass, call.Args[urlArg])
	}
}

func calledFunction(pass *analysis.Pass, call *ast.CallExpr) *types.Func {
	switch function := call.Fun.(type) {
	case *ast.Ident:
		fn, _ := pass.TypesInfo.Uses[function].(*types.Func)
		return fn
	case *ast.SelectorExpr:
		fn, _ := pass.TypesInfo.Uses[function.Sel].(*types.Func)
		return fn
	default:
		return nil
	}
}

func checkURL(pass *analysis.Pass, expr ast.Expr) {
	value := pass.TypesInfo.Types[expr].Value
	if value == nil || value.Kind() != constant.String {
		return
	}
	rawURL := constant.StringVal(value)
	parsed, err := url.Parse(rawURL)
	if err != nil || parsed.Scheme == "" {
		return
	}
	if !strings.EqualFold(parsed.Scheme, "https") {
		pass.Reportf(expr.Pos(), "hardcoded HTTP validator endpoint %q uses scheme %q; use HTTPS", rawURL, parsed.Scheme)
	}
}
