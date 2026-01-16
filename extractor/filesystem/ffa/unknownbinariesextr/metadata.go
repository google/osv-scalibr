package unknownbinariesextr

import (
	pb "github.com/google/osv-scalibr/binary/proto/scan_result_go_proto"
	"github.com/opencontainers/go-digest"
)

// UnknownBinaryMetadata is the metadata for extracting unknown binaries and attributing them to known base images.
type UnknownBinaryMetadata struct {
	FileHash    digest.Digest
	Attribution Attribution
}

// Attribution is the attribution for an unknown binary.
type Attribution struct {
	BaseImage bool
}

// SetProto sets the metadata for a package.
func (m *UnknownBinaryMetadata) SetProto(p *pb.Package) {
	if m == nil {
		return
	}

	attribution := &pb.UnknownBinaryAttribution{
		BaseImage: m.Attribution.BaseImage,
	}

	p.Metadata = &pb.Package_UnknownBinaryMetadata{
		UnknownBinaryMetadata: &pb.UnknownBinaryMetadata{
			FileHash:    string(m.FileHash),
			Attribution: attribution,
		},
	}
}

// ToStruct converts the metadata to a struct.
func ToStruct(ubm *pb.UnknownBinaryMetadata) *UnknownBinaryMetadata {
	if ubm == nil {
		return nil
	}

	return &UnknownBinaryMetadata{
		FileHash: digest.Digest(ubm.GetFileHash()),
		Attribution: struct {
			BaseImage bool
		}{
			BaseImage: ubm.GetAttribution().GetBaseImage(),
		},
	}
}
