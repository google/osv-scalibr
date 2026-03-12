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

package bazel

import (
	"fmt"

	"github.com/bazelbuild/buildtools/build"
)

// loadMapping maps rule names to their source paths
type loadMapping map[string]string

// extensionInfo holds information about a use_extension call
type extensionInfo struct {
	BzlFile string // First argument (extension path)
	Name    string // Second argument (extension type)
}

// getAttributeStringValue extracts a single string value from an attribute
// It handles cases where the attribute value is a direct string or a variable reference
// and also where the variables are concatenated.
func getAttributeStringValue(rule *build.Rule, file *build.File, attrName string) string {
	attr := rule.Attr(attrName)
	if attr == nil {
		return ""
	}

	// resolve string values
	return getStringValueWithVisited(attr, file, make(map[string]bool))
}

// getStringValueWithVisited resolves a string value from a Bazel expression
// It handles direct string literals, variable references, and string concatenation
// The visited map prevents infinite recursion with circular references
func getStringValueWithVisited(expr build.Expr, file *build.File, visited map[string]bool) string {
	if expr == nil {
		return ""
	}

	switch e := expr.(type) {
	case *build.StringExpr:
		// Direct string literal
		return e.Value

	case *build.BinaryExpr:
		// Handle string concatenation with + operator
		if e.Op == "+" {
			// Recursively resolve both sides of the + operator
			leftValue := getStringValueWithVisited(e.X, file, visited)
			rightValue := getStringValueWithVisited(e.Y, file, visited)
			return leftValue + rightValue
		}
		return ""

	case *build.Ident:
		// Handle variable reference
		if file == nil || visited[e.Name] {
			return ""
		}

		// Mark this variable as visited to prevent circular references
		visited[e.Name] = true

		// Find the variable assignment in the file
		varValue := findStringVariableValueWithVisited(e.Name, file, visited)

		// Unmark the variable after we're done
		delete(visited, e.Name)

		return varValue
	}

	return ""
}

// findStringVariableValueWithVisited finds and resolves a variable's string value
// It handles the case where the variable might be defined as another expression
func findStringVariableValueWithVisited(varName string, file *build.File, visited map[string]bool) string {
	if file == nil {
		return ""
	}

	for _, stmt := range file.Stmt {
		if assign, ok := stmt.(*build.AssignExpr); ok {
			if lhs, ok := assign.LHS.(*build.Ident); ok && lhs.Name == varName {
				// Found the variable, resolve its value
				return getStringValueWithVisited(assign.RHS, file, visited)
			}
		}
	}

	return ""
}

// getAttributeArrayValues extracts all string values from an attribute that is expected to be a list
// It handles cases where the attribute value is a direct list or a variable reference
func getAttributeArrayValues(rule *build.Rule, file *build.File, attrName string) []string {
	var attributeValues []string

	attr := rule.Attr(attrName)
	attributeValues = append(attributeValues, getAttributeValues(attr, file)...)

	return attributeValues
}

// getAttributeValues is a common function to extract all string values from an attribute of a list type.
// This function delegates to getAttributeValuesWithVisited to handle recursive variable references properly.
func getAttributeValues(expr build.Expr, file *build.File) []string {
	// Use the recursive implementation with an empty visited map to handle nested variable references
	return getAttributeValuesWithVisited(expr, file, make(map[string]bool))
}

// getAttributeValuesWithVisited is a helper function that finds all string expressions recursively inside the lists
// assigned to the `expr` argument. It handles recursive variable references (var1 = var1 + ["value1"] + var3)
func getAttributeValuesWithVisited(expr build.Expr, file *build.File, visited map[string]bool) []string {
	var dependencies []string

	if expr == nil {
		return dependencies
	}

	switch e := expr.(type) {
	case *build.ListExpr:
		// Direct list of items
		for _, item := range e.List {
			if str, ok := item.(*build.StringExpr); ok {
				// Handle direct string literals
				dependencies = append(dependencies, str.Value)
			} else {
				// Handle variables or expressions that might resolve to strings
				stringValue := getStringValueWithVisited(item, file, visited)
				if stringValue != "" {
					dependencies = append(dependencies, stringValue)
				}
			}
		}

	case *build.BinaryExpr:
		// Handle expressions like: [":lib"] + VAR_DEPS or ARTIFACTS + MORE_ARTIFACTS
		if e.Op == "+" {
			// Process left side of the + operator
			leftDeps := getAttributeValuesWithVisited(e.X, file, visited)
			dependencies = append(dependencies, leftDeps...)

			// Process right side of the + operator
			rightDeps := getAttributeValuesWithVisited(e.Y, file, visited)
			dependencies = append(dependencies, rightDeps...)
		}

	case *build.Ident:
		// Handle variable references
		// Look up the variable in the file
		if file != nil && !visited[e.Name] {
			varDeps := findAndProcessVariableWithVisited(e.Name, file, visited)
			dependencies = append(dependencies, varDeps...)
		}
	}

	return dependencies
}

// findAndProcessVariableWithVisited is a helper function that tracks visited variables to prevent
// infinite recursion in case of circular dependencies
func findAndProcessVariableWithVisited(varName string, file *build.File, visited map[string]bool) []string {
	var dependencies []string

	if file == nil {
		return dependencies
	}

	// Check for circular dependencies
	if visited[varName] {
		// We've already visited this variable, stop recursion
		return dependencies
	}

	// Mark this variable as visited
	visited[varName] = true

	for _, stmt := range file.Stmt {
		if assign, ok := stmt.(*build.AssignExpr); ok {
			if lhs, ok := assign.LHS.(*build.Ident); ok && lhs.Name == varName {
				// Found the variable, process its value with the visited map
				varDeps := getAttributeValuesWithVisited(assign.RHS, file, visited)
				dependencies = append(dependencies, varDeps...)
				break
			}
		}
	}

	// We're done with this variable, unmark it
	delete(visited, varName)

	return dependencies
}

// findExtensionVariables identifies all variables that are assigned from use_extension
// Returns a map of variable names to their extension info (path and type)
func findExtensionVariables(file *build.File) map[string]extensionInfo {
	extensionVars := make(map[string]extensionInfo)

	for _, stmt := range file.Stmt {
		assign, ok := stmt.(*build.AssignExpr)
		if !ok {
			continue
		}
		// Check if it's a variable assignment
		lhs, ok := assign.LHS.(*build.Ident)
		if !ok {
			continue
		}
		// Check if RHS is a use_extension call
		call, ok := assign.RHS.(*build.CallExpr)
		if !ok {
			continue
		}
		ident, ok := call.X.(*build.Ident)
		if !ok || ident.Name != "use_extension" {
			continue
		}
		// Check if it has at least 2 arguments
		if len(call.List) < 2 {
			continue
		}

		// Get the first argument (extension bzlFile)
		var bzlFile string
		if pathExpr, ok := call.List[0].(*build.StringExpr); ok {
			bzlFile = pathExpr.Value
		}

		// Get the second argument (extension type)
		var extensionName string
		if typeExpr, ok := call.List[1].(*build.StringExpr); ok {
			extensionName = typeExpr.Value
		}

		// Record the variable name and its extension info
		extensionVars[lhs.Name] = extensionInfo{
			BzlFile: bzlFile,
			Name:    extensionName,
		}
	}

	return extensionVars
}

// findLoadStatements finds all load statements in a Bazel file and returns a mapping
// of rule names to their source paths
func findLoadStatements(file *build.File) loadMapping {
	loadMapping := make(loadMapping)

	for _, stmt := range file.Stmt {
		if loadStmt, ok := stmt.(*build.LoadStmt); ok {
			// Get the source path (first argument)
			source := loadStmt.Module.Value

			// Process all the rules loaded from this source
			for _, loadedRule := range loadStmt.To {
				// Extract the name of the loaded rule
				ruleName := loadedRule.Name
				// Map the rule name to its source path
				loadMapping[ruleName] = source
			}
		}
	}

	return loadMapping
}

// RuleAttributeResult holds the result of extracting a named attribute from a rule call
// that was imported via a load() statement.
type RuleAttributeResult struct {
	// RuleName is the name of the rule function that was called (e.g., "go_library").
	RuleName string
	// LoadPath is the source path from the load() statement (e.g., "@rules_go//docs/go/core:rules.bzl").
	LoadPath string
	// Values contains the resolved string values of the requested attribute.
	Values []string
}

// FindLoadedRuleAttributes finds all rule calls in a Bazel file that were imported via
// load() from the given loadPath, and extracts the specified attribute values from each call.
//
// For example, given a Bazel file containing:
//
//	load("@rules_go//docs/go/core:rules.bzl", "go_binary", "go_library", "go_test")
//	go_library(
//	    name = "basic_gazelle_lib",
//	    deps = ["@org_golang_x_net//html"],
//	)
//
// Calling FindLoadedRuleAttributes(data, "@rules_go//docs/go/core:rules.bzl", "deps") would return
// a result for "go_library" with the deps values.
//
// Parameters:
//   - input: raw bytes of the Bazel file
//   - loadPath: the source path to match in load() statements (e.g., "@rules_go//docs/go/core:rules.bzl")
//   - attrName: the attribute name to extract from matching rule calls (e.g., "deps")
//
// Returns a slice of RuleAttributeResult, one per matching rule call that has the attribute.
func FindLoadedRuleAttributes(input []byte, loadPath string, attrName string) ([]RuleAttributeResult, error) {
	f, err := build.Parse("default", input)
	if err != nil {
		return nil, fmt.Errorf("failed to parse Bazel file: %w", err)
	}

	return FindLoadedRuleAttributesFromFile(f, loadPath, attrName), nil
}

// FindLoadedRuleAttributesFromFile is like FindLoadedRuleAttributes but operates on an
// already-parsed *build.File.
func FindLoadedRuleAttributesFromFile(f *build.File, loadPath string, attrName string) []RuleAttributeResult {
	loads := findLoadStatements(f)

	var results []RuleAttributeResult

	for _, stmt := range f.Stmt {
		call, ok := stmt.(*build.CallExpr)
		if !ok {
			continue
		}

		x, ok := call.X.(*build.Ident)
		if !ok {
			continue
		}

		// Check if this rule was loaded from the specified path
		source, exists := loads[x.Name]
		if !exists || source != loadPath {
			continue
		}

		r := &build.Rule{Call: call}
		if r.Attr(attrName) == nil {
			continue
		}

		values := getAttributeArrayValues(r, f, attrName)
		results = append(results, RuleAttributeResult{
			RuleName: x.Name,
			LoadPath: source,
			Values:   values,
		})
	}

	return results
}
