package aspect

import (
	"regexp"
	"strings"
)

var (
	splitPattern   = regexp.MustCompile(`[+~]`)
	versionPattern = regexp.MustCompile(`^\d+[\.\d]*$`)
	commitPattern  = regexp.MustCompile(`^[0-9a-f]{40}$`)
)

func normalizeModuleName(name string) string {
	parts := splitPattern.Split(name, -1)
	var cleanParts []string
	for _, p := range parts {
		if p == "" {
			continue
		}
		if versionPattern.MatchString(p) || commitPattern.MatchString(p) {
			continue
		}
		cleanParts = append(cleanParts, p)
	}
	if len(cleanParts) > 0 {
		return cleanParts[len(cleanParts)-1]
	}
	return name
}

func getGoPkgNameFromURL(url string) string {
	if strings.Contains(url, "github.com/") {
		parts := strings.Split(url, "github.com/")
		if len(parts) > 1 {
			repoPath := strings.Split(parts[1], "/")
			if len(repoPath) >= 2 {
				return "github.com/" + repoPath[0] + "/" + repoPath[1]
			}
		}
	}
	return ""
}

// parseBzlmodName attempts to un-mangle Bzlmod canonical names into their native ecosystem names
// (e.g. npm__at_babel_core -> @babel/core, pip__requests -> requests)
func parseBzlmodName(name string, purlType *string) string {
	parts := strings.SplitN(name, "__", 2)
	if len(parts) == 2 {
		prefix := parts[0]
		pkg := parts[1]
		if strings.HasPrefix(prefix, "npm") {
			*purlType = "npm"
			if after, found := strings.CutPrefix(pkg, "at_"); found {
				pkg = "@" + after
				// Find the first underscore and replace it with a slash
				pkg = strings.Replace(pkg, "_", "/", 1)
			}
			return pkg
		} else if strings.HasPrefix(prefix, "pypi") || strings.HasPrefix(prefix, "pip") || strings.HasPrefix(prefix, "rules_python") {
			*purlType = "pypi"
			// Python package names typically use dashes for canonical names in PyPI, but bzlmod often preserves underscores.
			// SCALIBR normalization handles this downstream.
			return pkg
		} else if strings.HasPrefix(prefix, "crates") {
			*purlType = "cargo"
			return strings.Split(pkg, "-")[0]
		}
	}
	return name
}
