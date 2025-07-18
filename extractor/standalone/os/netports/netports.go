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
	"github.com/google/osv-scalibr/plugin"
	psutilnet "github.com/shirou/gopsutil/net"
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

	connections, err := psutilnet.ConnectionsWithContext(ctx, "tcp")
	if err != nil {
		return inventory.Inventory{}, err
	}

	for _, c := range connections {
		// only consider listening TCP connections
		if c.Status != "LISTEN" {
			continue
		}

		// Skip loopback connections.
		laddrIP := net.ParseIP(c.Laddr.IP)
		if laddrIP.IsLoopback() {
			continue
		}

		processInfo, err := process.NewProcess(c.Pid)
		if err != nil {
			continue
		}

		cmdline, err := processInfo.Cmdline()
		if err != nil {
			continue
		}

		packages = append(packages, e.newPackage(c.Laddr.Port, "tcp", cmdline))
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
