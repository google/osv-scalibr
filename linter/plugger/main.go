package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"regexp"

	"github.com/google/osv-scalibr/linter/plugger/plugger"
)

var (
	fIPattern          string
	fExcludePkgPattern string
)

func init() {
	flag.StringVar(&fIPattern, "interface", "", `regex pattern for plugin interfaces, ex: 'github\.com/package.MyInterface|.*\.OtherInterface'`)
	// setting a^ as default to include everything
	flag.StringVar(&fExcludePkgPattern, "exclude-pkg", "a^", `regex pattern for pkg to exclude, ex: 'github\.com/package/testing/.*'`)
}

func main() {
	flag.Parse()

	pkgs := flag.Args()

	if fIPattern == "" {
		log.Fatal("please provide interface pattern")
	}

	iPattern, err := regexp.Compile(fIPattern)
	if err != nil {
		log.Fatal(err)
	}

	excludePkgPattern, err := regexp.Compile(fExcludePkgPattern)
	if err != nil {
		log.Fatal(err)
	}

	ctrs, err := plugger.Run(iPattern, excludePkgPattern, pkgs)
	if err != nil {
		log.Fatal(err)
	}

	cwd, err := os.Getwd()
	if err != nil {
		log.Fatal(err)
	}

	for _, c := range ctrs {
		pos, _ := c.Pos(cwd)
		shortObjName := c.Impl.Obj().Pkg().Name() + "." + c.Impl.Obj().Name()
		fmt.Printf("%s: plugger: %s is not registered\n", pos, shortObjName)
	}

	if len(ctrs) != 0 {
		os.Exit(1)
	}
}
