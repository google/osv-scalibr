package fakeserver

import (
	"archive/zip"
	"bytes"
	"encoding/base64"
	"encoding/binary"
	"hash/crc32"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/ossf/osv-schema/bindings/go/osvschema"
	"google.golang.org/protobuf/encoding/protojson"
)

func CreateZipServer(t *testing.T, handler http.HandlerFunc) *httptest.Server {
	t.Helper()

	ts := httptest.NewServer(handler)

	t.Cleanup(ts.Close)

	return ts
}

func ComputeCRC32CHash(t *testing.T, data []byte) string {
	t.Helper()

	hash := crc32.Checksum(data, crc32.MakeTable(crc32.Castagnoli))

	return base64.StdEncoding.EncodeToString(binary.BigEndian.AppendUint32([]byte{}, hash))
}

func WriteOSVsZip(t *testing.T, w http.ResponseWriter, osvs map[string]*osvschema.Vulnerability) (int, error) {
	t.Helper()

	z := ZipOSVs(t, osvs)

	w.Header().Add("x-goog-hash", "crc32c="+ComputeCRC32CHash(t, z))

	return w.Write(z)
}

func ZipOSVs(t *testing.T, osvs map[string]*osvschema.Vulnerability) []byte {
	t.Helper()

	buf := new(bytes.Buffer)
	writer := zip.NewWriter(buf)

	for fp, osv := range osvs {
		data, err := protojson.Marshal(osv)
		if err != nil {
			t.Fatalf("could not marshal %v: %v", osv, err)
		}

		f, err := writer.Create(fp)
		if err != nil {
			t.Fatal(err)
		}
		_, err = f.Write(data)
		if err != nil {
			t.Fatal(err)
		}
	}

	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}

	return buf.Bytes()
}
