// Copyright 2026 Google LLC
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

// Package nettraffic extracts files from pcap/pcapng files.
package nettraffic

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcapgo"
	cpb "github.com/google/osv-scalibr/binary/proto/config_go_proto"
	"github.com/google/osv-scalibr/extractor/filesystem"
	"github.com/google/osv-scalibr/extractor/filesystem/embeddedfs/common"
	scalibrfs "github.com/google/osv-scalibr/fs"
	"github.com/google/osv-scalibr/inventory"
	"github.com/google/osv-scalibr/plugin"
)

// Name is the unique name of this extractor.
const Name = "embeddedfs/nettraffic"

// Extractor extracts files from pcap and pcapng files.
type Extractor struct{}

// New returns a new pcap extractor.
func New(_ *cpb.PluginConfig) (filesystem.Extractor, error) {
	return &Extractor{}, nil
}

// NewDefault returns a new pcap extractor.
func NewDefault(_ *cpb.PluginConfig) (filesystem.Extractor, error) {
	return &Extractor{}, nil
}

// Name of the extractor.
func (e Extractor) Name() string {
	return Name
}

// Version of the extractor.
func (e Extractor) Version() int {
	return 0
}

// Requirements of the extractor.
func (e Extractor) Requirements() *plugin.Capabilities {
	return &plugin.Capabilities{}
}

// FileRequired returns true if the file should be extracted.
func (e Extractor) FileRequired(api filesystem.FileAPI) bool {
	ext := strings.ToLower(filepath.Ext(api.Path()))
	return ext == ".pcap" || ext == ".pcapng"
}

// Extract extracts files from pcap/pcapng files.
func (e Extractor) Extract(ctx context.Context, input *filesystem.ScanInput) (inventory.Inventory, error) {

	ext := strings.ToLower(filepath.Ext(input.Path))
	var packetSource *gopacket.PacketSource

	if ext == ".pcapng" {
		reader, err := pcapgo.NewNgReader(input.Reader, pcapgo.DefaultNgReaderOptions)
		if err != nil {
			return inventory.Inventory{}, fmt.Errorf("failed to open pcapng reader: %w", err)
		}
		packetSource = gopacket.NewPacketSource(reader, reader.LinkType())
	} else {
		reader, err := pcapgo.NewReader(input.Reader)
		if err != nil {
			return inventory.Inventory{}, fmt.Errorf("failed to open pcap reader: %w", err)
		}
		packetSource = gopacket.NewPacketSource(reader, reader.LinkType())
	}

	tempDir, err := os.MkdirTemp("", "pcap_extraction_*")
	if err != nil {
		return inventory.Inventory{}, fmt.Errorf("failed to create temp dir: %w", err)
	}

	fileMap := make(map[string][]byte)

	for packet := range packetSource.Packets() {
		if app := packet.ApplicationLayer(); app != nil {
			payload := app.Payload()
			if len(payload) > 0 {
				var src, dst string
				if net := packet.NetworkLayer(); net != nil {
					src = net.NetworkFlow().Src().String()
					dst = net.NetworkFlow().Dst().String()
				}

				var srcPort, dstPort string
				var protocol string
				if tcp := packet.Layer(layers.LayerTypeTCP); tcp != nil {
					protocol = "TCP"
					tcpLayer := tcp.(*layers.TCP)
					srcPort = tcpLayer.SrcPort.String()
					dstPort = tcpLayer.DstPort.String()
				} else if udp := packet.Layer(layers.LayerTypeUDP); udp != nil {
					protocol = "UDP"
					udpLayer := udp.(*layers.UDP)
					srcPort = udpLayer.SrcPort.String()
					dstPort = udpLayer.DstPort.String()
				}

				if protocol != "" {
					filename := fmt.Sprintf("%s_%s_%s_%s_to_%s_%s.txt", protocol, protocol, src, srcPort, dst, dstPort)
					filename = strings.ReplaceAll(filename, ":", "_") // Sanitize for filesystem

					if _, exists := fileMap[filename]; !exists {
						fileMap[filename] = append([]byte{}, payload...)
					} else {
						fileMap[filename] = append(fileMap[filename], payload...)
					}
				}
			}
		}
	}

	for filename, payload := range fileMap {
		filePath := filepath.Join(tempDir, filename)
		os.WriteFile(filePath, payload, 0644)
	}

	var refCount int32 = 1
	var refMu sync.Mutex
	getEmbeddedFS := func(ctx context.Context) (scalibrfs.FS, error) {
		return &common.EmbeddedDirFS{
			FS:       scalibrfs.DirFS(tempDir),
			File:     nil,
			TmpPaths: []string{tempDir},
			RefCount: &refCount,
			RefMu:    &refMu,
		}, nil
	}

	return inventory.Inventory{
		EmbeddedFSs: []*inventory.EmbeddedFS{
			{
				Path:          input.Path,
				GetEmbeddedFS: getEmbeddedFS,
			}},
	}, nil
}
