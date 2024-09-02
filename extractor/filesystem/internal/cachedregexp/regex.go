// Package cachedregexp provides a cached MustCompile alternative to regexp
package cachedregexp

import (
	"regexp"
	"sync"
)

var cache sync.Map

// MustCompile returns the same Regexp that regexp.MustCompile returns.
// The difference is MustCompile will also cache the compiled regexp
// to a global cache, if the same input is called again, it will retrieve
// the Regexp from the cache instead of recompiling.
func MustCompile(exp string) *regexp.Regexp {
	compiled, ok := cache.Load(exp)
	if !ok {
		compiled, _ = cache.LoadOrStore(exp, regexp.MustCompile(exp))
	}

	return compiled.(*regexp.Regexp)
}
