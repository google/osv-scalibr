package plugger

import (
	"go/types"
	"regexp"
	"sync"

	"golang.org/x/tools/go/packages"
)

// FindInterfaces returns all interfaces that follow the specified pattern
func FindInterfaces(pkgs []*packages.Package, iPattern *regexp.Regexp) []*types.Named {
	result := []*types.Named{}

	var mu sync.Mutex
	var wg sync.WaitGroup

	for _, pkg := range pkgs {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for ident, obj := range pkg.TypesInfo.Defs {
				if obj == nil {
					continue
				}
				named, ok := obj.Type().(*types.Named)
				if !ok {
					continue
				}

				if _, ok := named.Underlying().(*types.Interface); !ok {
					continue
				}
				if !iPattern.MatchString(pkg.Name + "." + ident.Name) {
					continue
				}
				mu.Lock()
				result = append(result, named)
				mu.Unlock()
			}
		}()
	}
	wg.Wait()
	return result
}
