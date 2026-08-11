package aspect

import (
	"regexp"
	"strings"
)

func normalizeModuleName(name string) string {
	parts := regexp.MustCompile(`[+~]`).Split(name, -1)
	var cleanParts []string
	for _, p := range parts {
		if p == "" {
			continue
		}
		if regexp.MustCompile(`^\d+[\.\d]*$`).MatchString(p) || regexp.MustCompile(`^[0-9a-f]{40}$`).MatchString(p) {
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
