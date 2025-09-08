package bazelmaven

import (
	"github.com/bazelbuild/buildtools/build"
)

// LoadMapping maps rule names to their source paths
type LoadMapping map[string]string

// ExtensionInfo holds information about a use_extension call
type ExtensionInfo struct {
	BzlFile string // First argument (extension path)
	Name    string // Second argument (extension type)
}

// GetAttributeStringValue extracts a single string value from an attribute
// It handles cases where the attribute value is a direct string or a variable reference
// and also where the variables are concatenated.
func GetAttributeStringValue(rule *build.Rule, file *build.File, attrName string) string {
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

// GetAttributeArrayValues extracts all string values from an attribute that is expected to be a list
// It handles cases where the attribute value is a direct list or a variable reference
func GetAttributeArrayValues(rule *build.Rule, file *build.File, attrName string) []string {
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
func findExtensionVariables(file *build.File) map[string]ExtensionInfo {
	extensionVars := make(map[string]ExtensionInfo)

	for _, stmt := range file.Stmt {
		if assign, ok := stmt.(*build.AssignExpr); ok {
			// Check if it's a variable assignment
			if lhs, ok := assign.LHS.(*build.Ident); ok {
				// Check if RHS is a use_extension call
				if call, ok := assign.RHS.(*build.CallExpr); ok {
					if ident, ok := call.X.(*build.Ident); ok && ident.Name == "use_extension" {
						// Check if it has at least 2 arguments
						if len(call.List) >= 2 {
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
							extensionVars[lhs.Name] = ExtensionInfo{
								BzlFile: bzlFile,
								Name:    extensionName,
							}
						}
					}
				}
			}
		}
	}

	return extensionVars
}

// findLoadStatements finds all load statements in a Bazel file and returns a mapping
// of rule names to their source paths
func findLoadStatements(file *build.File) LoadMapping {
	loadMapping := make(LoadMapping)

	for _, stmt := range file.Stmt {
		if loadStmt, ok := stmt.(*build.LoadStmt); ok {
			// Get the source path (first argument)
			source := loadStmt.Module.Value

			// Process all the rules loaded from this source
			for i := range loadStmt.To {
				// Extract the name of the loaded rule
				ruleName := loadStmt.To[i].Name
				// Map the rule name to its source path
				loadMapping[ruleName] = source
			}
		}
	}

	return loadMapping
}
