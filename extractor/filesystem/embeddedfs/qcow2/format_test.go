package qcow2

import (
	"bytes"
	"encoding/binary"
	"os"
	"path/filepath"
	"testing"
)

func TestParseHeaderValidMinimal(t *testing.T) {
	buf := new(bytes.Buffer)

	h := header{
		Magic:           qcow2Magic,
		Version:         3,
		ClusterBits:     9, // 512
		Size:            1024,
		CryptMethod:     0,
		L1Size:          0,
		HeaderLength:    112,
		CompressionType: 0,
	}

	if err := binary.Write(buf, binary.BigEndian, &h); err != nil {
		t.Fatalf("failed to write header: %v", err)
	}

	// header extensions terminator
	if err := binary.Write(buf, binary.BigEndian, uint32(0)); err != nil {
		t.Fatalf("failed to write extension terminator: %v", err)
	}

	parsed, exts, err := parseHeader(bytes.NewReader(buf.Bytes()))
	if err != nil {
		t.Fatalf("parseHeader failed: %v", err)
	}
	if parsed.Magic != qcow2Magic {
		t.Fatalf("unexpected magic")
	}
	if len(exts) != 0 {
		t.Fatalf("expected no extensions")
	}
}

func TestParseHeaderInvalidMagic(t *testing.T) {
	buf := new(bytes.Buffer)

	h := header{
		Magic:   0xdeadbeef,
		Version: 3,
	}

	_ = binary.Write(buf, binary.BigEndian, &h)

	_, _, err := parseHeader(bytes.NewReader(buf.Bytes()))
	if err == nil {
		t.Fatalf("expected error for invalid magic")
	}
}

func TestParseHeaderUnsupportedVersion(t *testing.T) {
	buf := new(bytes.Buffer)

	h := header{
		Magic:   qcow2Magic,
		Version: 4,
	}

	_ = binary.Write(buf, binary.BigEndian, &h)

	_, _, err := parseHeader(bytes.NewReader(buf.Bytes()))
	if err == nil {
		t.Fatalf("expected error for unsupported version")
	}
}

func TestBitRangeMask(t *testing.T) {
	tests := []struct {
		start uint64
		end   uint64
		want  uint64
	}{
		{0, 0, 0x1},
		{0, 3, 0xF},
		{4, 7, 0xF0},
		{9, 55, ((uint64(1) << (55 - 9 + 1)) - 1) << 9},
	}

	for _, tt := range tests {
		got := BitRangeMask(tt.start, tt.end)
		if got != tt.want {
			t.Fatalf("BitRangeMask(%d,%d) = 0x%x, want 0x%x",
				tt.start, tt.end, got, tt.want)
		}
	}
}

func TestBitRangeMaskInvalidPanics(t *testing.T) {
	defer func() {
		if r := recover(); r == nil {
			t.Fatalf("expected panic for invalid bit range")
		}
	}()
	BitRangeMask(10, 5)
}

func TestAlignUp(t *testing.T) {
	tests := []struct {
		n     uint64
		align uint64
		want  uint64
	}{
		{0, 512, 0},
		{1, 512, 512},
		{512, 512, 512},
		{513, 512, 1024},
		{1023, 512, 1024},
	}

	for _, tt := range tests {
		got := alignUp(tt.n, tt.align)
		if got != tt.want {
			t.Fatalf("alignUp(%d,%d)=%d want %d",
				tt.n, tt.align, got, tt.want)
		}
	}
}

func TestConvertQCOW2ToRawMissingArgs(t *testing.T) {
	if err := convertQCOW2ToRaw("", "out.raw", ""); err == nil {
		t.Fatalf("expected error for missing input")
	}
	if err := convertQCOW2ToRaw("in.qcow2", "", ""); err == nil {
		t.Fatalf("expected error for missing output")
	}
}

func TestConvertQCOW2ToRawMinimalImage(t *testing.T) {
	tmp := t.TempDir()
	in := filepath.Join(tmp, "test.qcow2")
	out := filepath.Join(tmp, "out.raw")

	f, err := os.Create(in)
	if err != nil {
		t.Fatalf("failed to create input file: %v", err)
	}

	// Minimal QCOW2 header with no L1 table
	h := header{
		Magic:                 qcow2Magic,
		Version:               3,
		ClusterBits:           9,
		Size:                  0,
		CryptMethod:           0,
		L1Size:                0,
		L1TableOffset:         0,
		RefcountTableOffset:   0,
		RefcountTableClusters: 0,
		HeaderLength:          112,
		CompressionType:       0,
	}

	if err := binary.Write(f, binary.BigEndian, &h); err != nil {
		t.Fatalf("failed to write header: %v", err)
	}
	if err := binary.Write(f, binary.BigEndian, uint32(0)); err != nil {
		t.Fatalf("failed to write extension terminator: %v", err)
	}
	f.Close()

	if err := convertQCOW2ToRaw(in, out, ""); err != nil {
		t.Fatalf("convertQCOW2ToRaw failed: %v", err)
	}

	info, err := os.Stat(out)
	if err != nil {
		t.Fatalf("output file not created: %v", err)
	}
	if info.Size() != 0 {
		t.Fatalf("expected empty raw image, got %d bytes", info.Size())
	}
}
