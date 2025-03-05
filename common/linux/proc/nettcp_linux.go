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

package proc

import (
	"bufio"
	"context"
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"
)

const (
	// TCPStateListening represents the state of a listening connection.
	TCPStateListening = 0xA
)

var (
	errInvalidFileFormat   = fmt.Errorf("invalid format for proc net file")
	errInvalidState        = fmt.Errorf("invalid state in proc net file")
	errInvalidAddressBlock = fmt.Errorf("invalid address block format in proc net file")
	errInvalidAddressSize  = fmt.Errorf("invalid address size in proc net file")
)

// NetTCPInfo contains the parsed /proc/net/{tcp,tcp6} files.
type NetTCPInfo struct {
	Entries []*NetTCPEntry
}

// NetTCPEntry represents a single entry in the /proc/net/{tcp,tcp6} files.
type NetTCPEntry struct {
	LocalAddr *net.IP
	LocalPort uint32
	State     int
	Inode     int64
}

// ListeningNonLoopback returns all listening connections entries from the parsed net files that are
// not listening on the local loopback.
func (n *NetTCPInfo) ListeningNonLoopback() []*NetTCPEntry {
	var entries []*NetTCPEntry

	for _, entry := range n.Entries {
		if entry.State == TCPStateListening && !entry.LocalAddr.IsLoopback() {
			entries = append(entries, entry)
		}
	}

	return entries
}

// ParseNetTCP parses a /proc/net/{tcp,tcp6} file and creates a NetTCPInfo from it.
func ParseNetTCP(ctx context.Context, r io.Reader) (*NetTCPInfo, error) {
	info := &NetTCPInfo{}
	scanner := bufio.NewScanner(r)
	for scanner.Scan() {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}

		entry, err := parseLine(scanner.Text())
		if err != nil {
			return nil, err
		}

		if entry == nil {
			continue
		}

		info.Entries = append(info.Entries, entry)
	}

	return info, nil
}

func parseLine(line string) (*NetTCPEntry, error) {
	fields := strings.Fields(line)

	// expected format:
	// sl local_address rem_address st tx_queue rx_queue tr tm->when retrnsmt uid timeout inode
	if len(fields) < 10 {
		return nil, errInvalidFileFormat
	}

	// ignore the header line
	if fields[1] == "local_address" {
		return nil, nil
	}

	// `st` part.
	state, err := strconv.ParseInt(fields[3], 16, 32)
	if err != nil {
		return nil, errInvalidState
	}
	entry := &NetTCPEntry{}
	entry.State = int(state)

	// `local_address` part.
	localAddr, localPort, err := parseAddressBlock(fields[1])
	if err != nil {
		return nil, err
	}
	entry.LocalAddr = localAddr
	entry.LocalPort = localPort

	// `inode` part.
	inode, err := strconv.ParseInt(fields[9], 10, 64)
	if err != nil {
		return nil, err
	}
	entry.Inode = inode

	return entry, nil
}

// parseAddressBlock parses an `address:port` block. It performs the adequate conversion and
// endianness changes.
func parseAddressBlock(block string) (*net.IP, uint32, error) {
	b := strings.Split(block, ":")
	if len(b) != 2 {
		return nil, 0, errInvalidAddressBlock
	}

	addr, err := parseIP(b[0])
	if err != nil {
		return nil, 0, err
	}

	port, err := strconv.ParseUint(b[1], 16, 32)
	if err != nil {
		return nil, 0, err
	}

	return addr, uint32(port), nil
}

// parseIP parses a hex string into a net.IP.
func parseIP(hexa string) (*net.IP, error) {
	b, err := hex.DecodeString(hexa)
	if err != nil {
		return nil, err
	}

	if len(b) != 4 && len(b) != 16 {
		return nil, errInvalidAddressSize
	}

	// Note: we need to ensure endianness is reversed, hence the direct index access in the following
	// two situations.

	if len(b) == 4 {
		ip := net.IPv4(b[3], b[2], b[1], b[0])

		return &ip, nil
	}

	return &net.IP{
		b[3], b[2], b[1], b[0],
		b[7], b[6], b[5], b[4],
		b[11], b[10], b[9], b[8],
		b[15], b[14], b[13], b[12],
	}, nil
}
