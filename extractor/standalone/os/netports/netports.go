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

// Package netports extracts open ports on the system and maps them to running processes when
// possible.
package netports

// This package is highly EXPERIMENTAL. Its behavior and output are subject to change without prior
// notice. It has also not been tested extensively.
// Use at your own risk.

import (
	"context"
	"fmt"
	"net"

	"github.com/google/osv-scalibr/extractor"
	"github.com/google/osv-scalibr/extractor/standalone"
	"github.com/google/osv-scalibr/inventory"
	"github.com/google/osv-scalibr/log"
	"github.com/google/osv-scalibr/plugin"
	"github.com/shirou/gopsutil/process"
)

const (
	// Name is the unique name of this extractor.
	Name = "os/netports"
)

// Extractor extracts open ports on the system.
type Extractor struct{}

// New creates a new Extractor.
func New() standalone.Extractor {
	return &Extractor{}
}

// Name of the extractor.
func (e Extractor) Name() string { return Name }

// Version of the extractor.
func (e Extractor) Version() int { return 0 }

// Requirements of the extractor.
func (e Extractor) Requirements() *plugin.Capabilities {
	return &plugin.Capabilities{
		RunningSystem: true,
	}
}

// Extract extracts open ports on the system.
func (e Extractor) Extract(ctx context.Context, input *standalone.ScanInput) (inventory.Inventory, error) {
	var packages []*extractor.Package

	log.Infof("----DEBUG----: Getting all processes")
	// First, get all processes.
	processes, err := process.ProcessesWithContext(ctx)
	if err != nil {
		return inventory.Inventory{}, err
	}

	log.Infof("----DEBUG----: Found %d processes", len(processes))
	log.Infof("----DEBUG----: Processes: %v", processes)
	log.Infof("----DEBUG----: End processes")

	// Retrieve all open ports.
	for _, p := range processes {
		log.Infof("----DEBUG----: Processing process %v", p)
		cmdline, err := p.Cmdline()

		if err != nil {
			log.Infof("----DEBUG----: cmdline error: %v, skipping...", err)
			continue
		}
		// Get all connections of the process.
		log.Infof("----DEBUG----: cmdline: %v. Getting connections...", cmdline)

		connections, err := p.ConnectionsWithContext(ctx)
		if err != nil {
			continue
		}

		log.Infof("----DEBUG----: Found %d connections", len(connections))
		log.Infof("----DEBUG----: Connections: %v", connections)

		for _, c := range connections {
			// Only consider listening TCP connections.
			if c.Status != "LISTEN" {
				continue
			}

			// Skip loopback connections.
			log.Infof("----DEBUG----: Paring IP %v", c.Laddr.IP)
			laddrIP := net.ParseIP(c.Laddr.IP)
			if laddrIP.IsLoopback() {
				continue
			}

			log.Infof("----DEBUG----: Adding package %v", e.newPackage(c.Laddr.Port, "tcp", cmdline))
			packages = append(packages, e.newPackage(c.Laddr.Port, "tcp", cmdline))
		}
	}

	return inventory.Inventory{Packages: packages}, nil
}

func (e Extractor) newPackage(port uint32, protocol string, cmdline string) *extractor.Package {
	return &extractor.Package{
		Name: fmt.Sprintf("network-port-%d", port),
		Metadata: &Metadata{
			Port:     port,
			Protocol: protocol,
			Cmdline:  cmdline,
		},
	}
}
