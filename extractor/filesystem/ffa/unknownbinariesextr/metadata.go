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
	// Attributed to ecosystem (via package manager's db files)
	LocalFilesystem bool `json:"localFilesystem"`
	// Attributed to reputable base image available on deps.dev
	BaseImage bool `json:"baseImage"`
}

// SetProto sets the metadata for a package.
func (m *UnknownBinaryMetadata) SetProto(p *pb.Package) {
	if m == nil {
		return
	}

	attribution := &pb.UnknownBinaryAttribution{
		LocalFilesystem: m.Attribution.LocalFilesystem,
		BaseImage:       m.Attribution.BaseImage,
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

	attr := ubm.GetAttribution()

	return &UnknownBinaryMetadata{
		FileHash: digest.Digest(ubm.GetFileHash()),
		Attribution: Attribution{
			LocalFilesystem: attr.GetLocalFilesystem(),
			BaseImage:       attr.GetBaseImage(),
		},
	}
}
