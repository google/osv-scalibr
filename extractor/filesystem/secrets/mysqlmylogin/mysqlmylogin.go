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

// Package mysqlmylogin provides an extractor for identifying secrets in .mylogin.cnf files.
package mysqlmylogin

import (
	"context"
	"fmt"
	"path/filepath"

	"github.com/google/osv-scalibr/extractor/filesystem"
	"github.com/google/osv-scalibr/inventory"
	"github.com/google/osv-scalibr/plugin"

	"gopkg.in/ini.v1"
)

// MysqlMyloginSection is a Veles Secret that holds relevant information for a [Mysql MyLogin](https://dev.mysql.com/doc/refman/8.4/en/option-files.html).
type MysqlMyloginSection struct {
	SectionName string
	User        string
	Password    string
	Host        string
	Port        string
	Socket      string
}

const (
	// Name is the unique name of this extractor.
	Name = "secrets/mysqlmylogin"
)

// Extractor extracts mysql credentials from .mylogin.cnf files.
type Extractor struct{}

// New returns a .mylogin.cnf extractor.
func New() filesystem.Extractor { return &Extractor{} }

// Name of the extractor.
func (e Extractor) Name() string { return Name }

// Version of the extractor.
func (e Extractor) Version() int { return 0 }

// Requirements of the extractor.
func (e Extractor) Requirements() *plugin.Capabilities {
	return &plugin.Capabilities{}
}

// FileRequired returns true if the specified file is a .mylogin.cnf file.
func (e Extractor) FileRequired(api filesystem.FileAPI) bool {
	return filepath.Base(api.Path()) == ".mylogin.cnf"
}

// Extract extracts Mysql credentials from .mylogin.cnf file.
func (e Extractor) Extract(ctx context.Context, input *filesystem.ScanInput) (inventory.Inventory, error) {
	var secrets []*inventory.Secret

	plaintext, err := decryptMyLoginCNF(input.Reader)
	if err != nil {
		return inventory.Inventory{}, fmt.Errorf("error decrypting file %w", err)
	}

	cfg, err := ini.Load(plaintext)
	if err != nil {
		return inventory.Inventory{}, fmt.Errorf("unable to Load ini structure from %s", input.Path)
	}

	// Get all sections in the mylogin file
	sections := cfg.Sections()
	for _, section := range sections {
		// The ini library uses a "DEFAULT" section which is always empyt
		// skipping it
		if section.Name() == ini.DefaultSection {
			continue
		}

		// Get all key-value pairs
		keysMap := section.KeysHash()
		// Populate struct (keys that don't exist will just be "")
		s := MysqlMyloginSection{
			SectionName: section.Name(),
			Host:        keysMap["host"],
			User:        keysMap["user"],
			Password:    keysMap["password"],
			Port:        keysMap["port"],
			Socket:      keysMap["socket"],
		}

		secrets = append(secrets, &inventory.Secret{
			Secret:   s,
			Location: input.Path,
		})
	}
	return inventory.Inventory{Secrets: secrets}, nil
}
