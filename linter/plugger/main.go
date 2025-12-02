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

	"github.com/google/osv-scalibr/linter/plugger/flags"
	"github.com/google/osv-scalibr/linter/plugger/plugger"
)

var (
	fInterfaces flags.List
)

func setFlags() {
	flag.Var(&fInterfaces, "interface", `list of interfaces (repeatable), ex: '-interface github.com/pkg.Interface'`)
}

func main() {
	setFlags()
	flag.Parse()

	pkgs := flag.Args()

	if len(fInterfaces) == 0 {
		log.Fatal("please provide at least one plugin interface, ex: '-interface github.com/pkg.Interface'")
	}

	ctrs, err := plugger.Run(fInterfaces, pkgs)
	if err != nil {
		log.Fatal(err)
	}

	cwd, err := os.Getwd()
	if err != nil {
		log.Fatal(err)
	}

	for _, c := range ctrs {
		pos, err := c.Pos(cwd)
		if err != nil {
			log.Fatal(err)
		}
		fmt.Printf("%s: plugger: %s is not registered\n", pos, c.RegisteredType())
	}

	if len(ctrs) != 0 {
		os.Exit(1)
	}
}
