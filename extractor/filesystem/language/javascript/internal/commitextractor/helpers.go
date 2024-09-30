// Package commitextractor provides a function to extract commit hash from the full git URL
package commitextractor

import (
	"net/url"
	"regexp"
)

// language=GoRegExp
var matchers = []*regexp.Regexp{
	// ssh://...
	// git://...
	// git+ssh://...
	// git+https://...
	regexp.MustCompile(`(?:^|.+@)(?:git(?:\+(?:ssh|https))?|ssh)://.+#(\w+)$`),
	// https://....git/...
	regexp.MustCompile(`(?:^|.+@)https://.+\.git#(\w+)$`),
	regexp.MustCompile(`https://codeload\.github\.com(?:/[\w-.]+){2}/tar\.gz/(\w+)$`),
	regexp.MustCompile(`.+#commit[:=](\w+)$`),
	// github:...
	// gitlab:...
	// bitbucket:...
	regexp.MustCompile(`^(?:github|gitlab|bitbucket):.+#(\w+)$`),
}

// TryExtractCommit tries to extract the commit hash from a full git url.
func TryExtractCommit(resolution string) string {
	for _, re := range matchers {
		matched := re.FindStringSubmatch(resolution)

		if matched != nil {
			return matched[1]
		}
	}

	u, err := url.Parse(resolution)

	if err == nil {
		gitRepoHosts := []string{
			"bitbucket.org",
			"github.com",
			"gitlab.com",
		}

		for _, host := range gitRepoHosts {
			if u.Host != host {
				continue
			}

			if u.RawQuery != "" {
				queries := u.Query()

				if queries.Has("ref") {
					return queries.Get("ref")
				}
			}

			return u.Fragment
		}
	}

	return ""
}
