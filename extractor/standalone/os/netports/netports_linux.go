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

//go:build linux

// Package netports extracts open ports on the system and maps them to running processes when
// possible.
package netports

// This package is highly EXPERIMENTAL. Its behavior and output are subject to change without prior
// notice. It has also not been tested extensively.
// Use at your own risk.

import (
	"context"
	"fmt"
	"os"
	"strings"

	"github.com/google/osv-scalibr/common/linux/proc"
	"github.com/google/osv-scalibr/extractor"
	"github.com/google/osv-scalibr/extractor/standalone"
	"github.com/google/osv-scalibr/inventory"
	"github.com/google/osv-scalibr/plugin"
	"github.com/google/osv-scalibr/purl"
)

const (
	// Name is the unique name of this extractor.
	Name = "os/netports"
)

var (
	knownNetFiles = []string{
		"/proc/self/net/tcp",
		"/proc/self/net/tcp6",
	}
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
		OS:            plugin.OSLinux,
		RunningSystem: true,
	}
}

// Extract extracts open ports on the system.
func (e Extractor) Extract(ctx context.Context, input *standalone.ScanInput) (inventory.Inventory, error) {
	// First, extract a mapping that provides the PID for each open socket inode number.
	inodeToPID, err := proc.MapSocketInodesToPID(ctx, input.Root, input.FS)
	if err != nil {
		return inventory.Inventory{}, err
	}

	// Retrieve all open ports with their associated inode number.
	tcpInfos, err := e.allTCPInfo(ctx)
	if err != nil {
		return inventory.Inventory{}, err
	}

	// Maps socket inode -> PID -> command line. Tries to cache the command line when possible.
	pidCommandLinesCache := make(map[int64][]string)
	var packages []*extractor.Package

	proto := "tcp"
	for _, tcpInfo := range tcpInfos {
		for _, entry := range tcpInfo.ListeningNonLoopback() {
			port := entry.LocalPort
			pid, ok := inodeToPID[entry.Inode]
			if !ok {
				packages = append(packages, e.newPackage(port, proto, []string{"unknown"}))
				continue
			}

			cmdline, cached := pidCommandLinesCache[pid]
			if cached {
				packages = append(packages, e.newPackage(port, proto, cmdline))
				continue
			}

			cmdline, err := proc.ReadProcessCmdline(ctx, pid, input.Root, input.FS)
			if err != nil {
				return inventory.Inventory{}, err
			}

			pidCommandLinesCache[pid] = cmdline
			packages = append(packages, e.newPackage(port, proto, cmdline))
		}
	}

	return inventory.Inventory{Packages: packages}, nil
}

// ToPURL converts a package created by this extractor into a PURL.
// This extractor does not create PURLs.
func (e Extractor) ToPURL(p *extractor.Package) *purl.PackageURL {
	return nil
}

// Ecosystem returns no Ecosystem since the ecosystem is not known by OSV yet.
func (Extractor) Ecosystem(p *extractor.Package) string { return "" }

func (e Extractor) allTCPInfo(ctx context.Context) ([]*proc.NetTCPInfo, error) {
	var entries []*proc.NetTCPInfo

	for _, path := range knownNetFiles {
		info, err := e.extractPortsFromFile(ctx, path)
		if err != nil {
			return nil, err
		}

		entries = append(entries, info)
	}

	return entries, nil
}

func (e Extractor) extractPortsFromFile(ctx context.Context, path string) (*proc.NetTCPInfo, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	return proc.ParseNetTCP(ctx, f)
}

func (e Extractor) newPackage(port uint32, protocol string, cmdline []string) *extractor.Package {
	return &extractor.Package{
		Name: fmt.Sprintf("network-port-%d", port),
		Metadata: &Metadata{
			Port:     port,
			Protocol: protocol,
			Cmdline:  strings.Join(cmdline, "\x00"),
		},
	}
}
