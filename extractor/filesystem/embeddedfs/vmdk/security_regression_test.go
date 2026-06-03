package vmdk

import (
	"bytes"
	"compress/zlib"
	"encoding/binary"
	"os"
	"runtime"
	"testing"
)

// craftStreamOptimizedVMDKMarkerBomb builds a minimal stream-optimized VMDK
// whose first stream marker has size=0xffffffff.
// readStreamMarker calls make([]byte, size) before io.ReadFull returns EOF.
func craftStreamOptimizedVMDKMarkerBomb(t *testing.T) string {
	t.Helper()

	hdr := make([]byte, SectorSize) // 512 bytes, all-zero baseline
	le := binary.LittleEndian

	le.PutUint32(hdr[0:], SparseMagic) // MagicNumber
	le.PutUint32(hdr[4:], 1)           // Version = 1
	le.PutUint32(hdr[8:], 0x00030000)  // Flags = flagHasCompressed | flagHasMetadata
	le.PutUint64(hdr[12:], 1)          // Capacity = 1 sector
	le.PutUint64(hdr[20:], 128)        // GrainSize = 128 (default)
	// DescriptorOffset/DescriptorSize/NumGTEsPerGT/RGDOffset = 0
	le.PutUint64(hdr[56:], 1) // GDOffset = 1 (not GDAtEnd)
	le.PutUint64(hdr[64:], 2) // OverHead = 2 → stream starts at byte 1024
	hdr[72] = 0               // UncleanShutdown
	hdr[73] = '\n'            // SingleEndLineChar
	hdr[74] = ' '             // NonEndLineChar
	hdr[75] = '\r'            // DoubleEndLineChar1
	hdr[76] = '\n'            // DoubleEndLineChar2
	le.PutUint16(hdr[77:], 1) // CompressAlgorithm = 1 (deflate)

	// Pad to byte 1024 (sector 2 = OverHead * SectorSize)
	pad := make([]byte, SectorSize) // one more sector of zeros

	// Stream marker at byte 1024: val=0 (8 bytes) + size=0xffffffff (4 bytes)
	marker := make([]byte, 12)
	le.PutUint64(marker[0:], 0)          // val = LBA 0
	le.PutUint32(marker[8:], 0xffffffff) // size = ~4 GB → make([]byte, 4294967295)

	f, err := os.CreateTemp(t.TempDir(), "scalibr-vmdk-markerbomb-*.vmdk")
	if err != nil {
		t.Fatalf("CreateTemp: %v", err)
	}
	for _, b := range [][]byte{hdr, pad, marker} {
		if _, err := f.Write(b); err != nil {
			f.Close()
			t.Fatalf("Write: %v", err)
		}
	}
	f.Close()
	return f.Name()
}

func TestConvertVMDKStreamMarkerSizeRejected(t *testing.T) {
	inputPath := craftStreamOptimizedVMDKMarkerBomb(t)

	outFile, err := os.CreateTemp(t.TempDir(), "scalibr-vmdk-out-*.raw")
	if err != nil {
		t.Fatalf("CreateTemp output: %v", err)
	}
	outFile.Close()

	t.Logf("Malicious stream-optimized VMDK: 1036 bytes on disk")
	t.Logf("Marker size = 0xffffffff => make([]byte, 4294967295) = ~4 GB attempted without fix")

	var msBefore, msAfter runtime.MemStats
	runtime.ReadMemStats(&msBefore)

	convertErr := convertVMDKToRaw(inputPath, outFile.Name())

	runtime.ReadMemStats(&msAfter)
	allocMB := (msAfter.TotalAlloc - msBefore.TotalAlloc) >> 20

	t.Logf("convertVMDKToRaw err: %v", convertErr)
	t.Logf("TotalAlloc delta: %d MB", allocMB)

	if convertErr == nil {
		t.Errorf("expected error for malicious marker size=0xffffffff, got nil")
	}
	if allocMB > 50 {
		t.Errorf("TotalAlloc delta %d MB exceeds 50 MB — marker size bounds check missing", allocMB)
	}
}

// craftStreamOptimizedVMDKFooterBomb builds a stream-optimized VMDK with a
// FOOTER metadata marker (size=0, typ=3) whose sector-count val is 0x100000
// (~512 MB allocation via make([]byte, val*SectorSize)).
func craftStreamOptimizedVMDKFooterBomb(t *testing.T) string {
	t.Helper()

	hdr := make([]byte, SectorSize)
	le := binary.LittleEndian
	le.PutUint32(hdr[0:], SparseMagic)
	le.PutUint32(hdr[4:], 1)
	le.PutUint32(hdr[8:], 0x00030000) // stream-optimized flags
	le.PutUint64(hdr[12:], 1)
	le.PutUint64(hdr[20:], 128)
	le.PutUint64(hdr[56:], 1) // GDOffset != GDAtEnd
	le.PutUint64(hdr[64:], 2) // OverHead = 2 → stream at byte 1024
	hdr[73] = '\n'
	hdr[74] = ' '
	hdr[75] = '\r'
	hdr[76] = '\n'
	le.PutUint16(hdr[77:], 1)

	pad := make([]byte, SectorSize)

	// Metadata marker: size=0 (→ read typ), val=0x100000 sectors (~512 MB), typ=3 (FOOTER)
	meta := make([]byte, 16)
	le.PutUint64(meta[0:], 0x100000) // val = 1M sectors → 512 MB allocation
	le.PutUint32(meta[8:], 0)        // size = 0 → metadata path
	le.PutUint32(meta[12:], 3)       // typ = 3 (FOOTER) → make([]byte, val*SectorSize)

	f, err := os.CreateTemp(t.TempDir(), "scalibr-vmdk-footerbomb-*.vmdk")
	if err != nil {
		t.Fatalf("CreateTemp: %v", err)
	}
	for _, b := range [][]byte{hdr, pad, meta} {
		if _, err := f.Write(b); err != nil {
			f.Close()
			t.Fatalf("Write: %v", err)
		}
	}
	f.Close()
	return f.Name()
}

// craftStreamOptimizedVMDKGrainOverflow builds a stream-optimized VMDK whose
// GrainSize is an oversized power of two (2^62). It passes the old
// power-of-two check, but int64(grainSec)*SectorSize overflows int64 and wraps
// to 0, so the subsequent grain-alignment arithmetic divides by zero.
func craftStreamOptimizedVMDKGrainOverflow(t *testing.T) string {
	t.Helper()

	hdr := make([]byte, SectorSize)
	le := binary.LittleEndian
	le.PutUint32(hdr[0:], SparseMagic)
	le.PutUint32(hdr[4:], 1)
	le.PutUint32(hdr[8:], 0x00030000)     // stream-optimized flags
	le.PutUint64(hdr[12:], 1)             // Capacity = 1 sector
	le.PutUint64(hdr[20:], uint64(1)<<62) // GrainSize = 2^62 (power of two, overflows *512)
	le.PutUint64(hdr[56:], 1)             // GDOffset != GDAtEnd
	le.PutUint64(hdr[64:], 2)             // OverHead = 2 → stream at byte 1024
	hdr[73] = '\n'
	hdr[74] = ' '
	hdr[75] = '\r'
	hdr[76] = '\n'
	le.PutUint16(hdr[77:], 1)

	pad := make([]byte, SectorSize)

	// A valid zlib-compressed grain so parsing reaches the alignment math.
	var zbuf bytes.Buffer
	zw := zlib.NewWriter(&zbuf)
	if _, err := zw.Write([]byte("grain")); err != nil {
		t.Fatalf("zlib write: %v", err)
	}
	if err := zw.Close(); err != nil {
		t.Fatalf("zlib close: %v", err)
	}
	comp := zbuf.Bytes()

	marker := make([]byte, 12)
	le.PutUint64(marker[0:], 0)                 // val = LBA 0
	le.PutUint32(marker[8:], uint32(len(comp))) // size = compressed length

	// Pad the grain marker out to a sector boundary, then append an EOS marker.
	consumed := 12 + len(comp)
	grainPad := (SectorSize - (consumed % SectorSize)) % SectorSize
	eos := make([]byte, 16) // val=0, size=0, typ=0 (EOS)

	f, err := os.CreateTemp(t.TempDir(), "scalibr-vmdk-grainoverflow-*.vmdk")
	if err != nil {
		t.Fatalf("CreateTemp: %v", err)
	}
	for _, b := range [][]byte{hdr, pad, marker, comp, make([]byte, grainPad), eos} {
		if _, err := f.Write(b); err != nil {
			f.Close()
			t.Fatalf("Write: %v", err)
		}
	}
	f.Close()
	return f.Name()
}

func TestConvertVMDKGrainSizeOverflowHandled(t *testing.T) {
	inputPath := craftStreamOptimizedVMDKGrainOverflow(t)

	outFile, err := os.CreateTemp(t.TempDir(), "scalibr-vmdk-out-*.raw")
	if err != nil {
		t.Fatalf("CreateTemp output: %v", err)
	}
	outFile.Close()

	t.Logf("GrainSize = 2^62 => int64(grainSec)*SectorSize overflows to 0 without the cap")

	// Without the MaxGrainSec cap, grainBytes wraps to 0 and the grain-alignment
	// arithmetic panics with an integer divide-by-zero. The cap forces a fallback
	// to DefaultGrainSec, so the conversion completes without panicking.
	defer func() {
		if r := recover(); r != nil {
			t.Errorf("convertVMDKToRaw panicked on oversized GrainSize: %v", r)
		}
	}()

	if err := convertVMDKToRaw(inputPath, outFile.Name()); err != nil {
		t.Logf("convertVMDKToRaw err (non-fatal, must not panic): %v", err)
	}
}

func TestConvertVMDKFooterSectorCountRejected(t *testing.T) {
	inputPath := craftStreamOptimizedVMDKFooterBomb(t)

	outFile, err := os.CreateTemp(t.TempDir(), "scalibr-vmdk-out-*.raw")
	if err != nil {
		t.Fatalf("CreateTemp output: %v", err)
	}
	outFile.Close()

	t.Logf("Malicious FOOTER marker: val=0x100000 sectors => ~512 MB allocation without fix")

	var msBefore, msAfter runtime.MemStats
	runtime.ReadMemStats(&msBefore)

	convertErr := convertVMDKToRaw(inputPath, outFile.Name())

	runtime.ReadMemStats(&msAfter)
	allocMB := (msAfter.TotalAlloc - msBefore.TotalAlloc) >> 20

	t.Logf("convertVMDKToRaw err: %v", convertErr)
	t.Logf("TotalAlloc delta: %d MB", allocMB)

	if convertErr == nil {
		t.Errorf("expected error for malicious footer val=0x100000, got nil")
	}
	if allocMB > 50 {
		t.Errorf("TotalAlloc delta %d MB exceeds 50 MB — footer sector count bounds check missing", allocMB)
	}
}
