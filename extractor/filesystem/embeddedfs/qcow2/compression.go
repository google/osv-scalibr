package qcow2

import (
	"bytes"
	"compress/flate"
	"fmt"
	"io"
)

// decompressRawDeflate decompresses raw deflate data to the specified size
func decompressRawDeflate(compressed []byte, decompressedSize uint64) ([]byte, error) {
	r := flate.NewReader(bytes.NewReader(compressed))
	defer r.Close()
	decompressed := make([]byte, decompressedSize)
	if _, err := io.ReadFull(r, decompressed); err != nil {
		return nil, fmt.Errorf("failed to decompress raw deflate: %w", err)
	}
	return decompressed, nil
}
