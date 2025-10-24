// Copyright 2025 Google LLC
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

// The plugger command is used to flag plugins which are not registered
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

func setFlags() {
	flag.StringVar(&fIPattern, "interface", "", `regex pattern for plugin interfaces, ex: 'github\.com/package.MyInterface|.*\.OtherInterface'`)
	// setting a^ as default to include everything
	flag.StringVar(&fExcludePkgPattern, "exclude-pkg", "a^", `regex pattern for pkg to exclude, ex: 'github\.com/package/testing/.*'`)
}

func main() {
	setFlags()
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
