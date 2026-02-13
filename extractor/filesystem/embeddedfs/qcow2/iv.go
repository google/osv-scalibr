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
