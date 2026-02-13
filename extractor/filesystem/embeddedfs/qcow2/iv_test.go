package qcow2

import (
	"bytes"
	"crypto/aes"
	"encoding/binary"
	"testing"
)

func TestPlainIVGen(t *testing.T) {
	tests := []struct {
		name   string
		sector uint64
		niv    int
		want   []byte
	}{
		{
			name:   "32bit exact",
			sector: 0x11223344,
			niv:    4,
			want:   []byte{0x44, 0x33, 0x22, 0x11},
		},
		{
			name:   "32bit padded",
			sector: 0x11223344,
			niv:    8,
			want:   []byte{0x44, 0x33, 0x22, 0x11, 0, 0, 0, 0},
		},
		{
			name:   "niv less than 4",
			sector: 0x11223344,
			niv:    2,
			want:   []byte{0x44, 0x33},
		},
	}

	gen := &PlainIVGen{}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			iv, err := gen.Calculate(tt.sector, tt.niv)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if !bytes.Equal(iv, tt.want) {
				t.Fatalf("got %x, want %x", iv, tt.want)
			}
		})
	}
}

func TestPlain64IVGen(t *testing.T) {
	tests := []struct {
		name   string
		sector uint64
		niv    int
		want   []byte
	}{
		{
			name:   "64bit exact",
			sector: 0x1122334455667788,
			niv:    8,
			want:   []byte{0x88, 0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11},
		},
		{
			name:   "64bit padded",
			sector: 0x1122334455667788,
			niv:    16,
			want:   append([]byte{0x88, 0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11}, make([]byte, 8)...),
		},
		{
			name:   "niv less than 8",
			sector: 0x1122334455667788,
			niv:    4,
			want:   []byte{0x88, 0x77, 0x66, 0x55},
		},
	}

	gen := &Plain64IVGen{}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			iv, err := gen.Calculate(tt.sector, tt.niv)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if !bytes.Equal(iv, tt.want) {
				t.Fatalf("got %x, want %x", iv, tt.want)
			}
		})
	}
}

func TestESSIVGen(t *testing.T) {
	key := make([]byte, 16) // zero key for deterministic test
	block, err := aes.NewCipher(key)
	if err != nil {
		t.Fatalf("failed to create AES cipher: %v", err)
	}

	gen := &ESSIVGen{cipher: block}

	sector := uint64(0xdeadbeef)
	niv := 16

	iv, err := gen.Calculate(sector, niv)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Recompute expected value manually
	data := make([]byte, block.BlockSize())
	binary.LittleEndian.PutUint64(data, sector)
	expected := make([]byte, block.BlockSize())
	block.Encrypt(expected, data)

	if !bytes.Equal(iv, expected[:niv]) {
		t.Fatalf("got %x, want %x", iv, expected[:niv])
	}
}

func TestESSIVGenPadding(t *testing.T) {
	key := make([]byte, 16)
	block, _ := aes.NewCipher(key)
	gen := &ESSIVGen{cipher: block}

	iv, err := gen.Calculate(1, 32)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(iv) != 32 {
		t.Fatalf("expected iv length 32, got %d", len(iv))
	}

	for i := block.BlockSize(); i < len(iv); i++ {
		if iv[i] != 0 {
			t.Fatalf("expected zero padding at index %d", i)
		}
	}
}
