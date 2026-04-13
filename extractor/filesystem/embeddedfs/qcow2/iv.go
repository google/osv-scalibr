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

package qcow2

import (
	"crypto/cipher"
	"encoding/binary"
)

// IVGenAlgorithm defines the interface for IV generation
type IVGenAlgorithm interface {
	Calculate(sector uint64, niv int) ([]byte, error)
}

// PlainIVGen implements plain IV generation (32-bit LE sector)
type PlainIVGen struct{}

// Plain64IVGen implements plain64 IV generation (64-bit LE sector)
type Plain64IVGen struct{}

// ESSIVGen implements ESSIV IV generation
type ESSIVGen struct {
	cipher cipher.Block // AES-ECB cipher for ESSIV
}

// Calculate generates plain IV
func (p *PlainIVGen) Calculate(sector uint64, niv int) ([]byte, error) {
	iv := make([]byte, niv)
	ivprefix := min(4, niv)
	shortsector := uint32(sector & 0xffffffff)
	var sectorBytes [4]byte
	binary.LittleEndian.PutUint32(sectorBytes[:], shortsector)
	copy(iv, sectorBytes[:ivprefix])
	if ivprefix < niv {
		for i := ivprefix; i < niv; i++ {
			iv[i] = 0
		}
	}
	return iv, nil
}

// Calculate generates plain64 IV
func (p *Plain64IVGen) Calculate(sector uint64, niv int) ([]byte, error) {
	iv := make([]byte, niv)
	ivprefix := min(8, niv)
	var sectorBytes [8]byte
	binary.LittleEndian.PutUint64(sectorBytes[:], sector)
	copy(iv, sectorBytes[:ivprefix])
	if ivprefix < niv {
		for i := ivprefix; i < niv; i++ {
			iv[i] = 0
		}
	}
	return iv, nil
}

// Calculate generates ESSIV IV
func (e *ESSIVGen) Calculate(sector uint64, niv int) ([]byte, error) {
	ndata := e.cipher.BlockSize()
	data := make([]byte, ndata)
	ivprefix := min(ndata, niv)
	var sectorBytes [8]byte
	binary.LittleEndian.PutUint64(sectorBytes[:], sector)
	copy(data, sectorBytes[:min(8, ndata)])
	if 8 < ndata {
		for i := 8; i < ndata; i++ {
			data[i] = 0
		}
	}
	dst := make([]byte, ndata)
	e.cipher.Encrypt(dst, data)
	iv := make([]byte, niv)
	copy(iv, dst[:ivprefix])
	if ivprefix < niv {
		for i := ivprefix; i < niv; i++ {
			iv[i] = 0
		}
	}
	return iv, nil
}
