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

package proto

import (
	"compress/gzip"
	"errors"
	"os"
	"path/filepath"
	"strings"

	"github.com/google/osv-scalibr/log"
	"google.golang.org/protobuf/encoding/prototext"
	"google.golang.org/protobuf/proto"
)

// fileType represents the type of a proto result file.
type fileType struct {
	isGZipped  bool
	isBinProto bool
}

// typeForPath returns the proto type of a path, or an error if the path is not a valid proto file.
func typeForPath(filePath string) (*fileType, error) {
	ext := filepath.Ext(filePath)
	if ext == "" {
		return nil, errors.New("invalid filename: Doesn't have an extension")
	}

	isGZipped := false
	if ext == ".gz" {
		isGZipped = true
		ext = filepath.Ext(strings.TrimSuffix(filePath, ext))
		if ext == "" {
			return nil, errors.New("invalid filename: Gzipped file doesn't have an extension")
		}
	}

	var isBinProto bool
	switch ext {
	case ".binproto":
		isBinProto = true
	case ".textproto":
		isBinProto = false
	default:
		return nil, errors.New("invalid filename: not a .textproto or .binproto")
	}

	return &fileType{isGZipped: isGZipped, isBinProto: isBinProto}, nil
}

// ValidExtension returns an error if the file extension is not a proto file.
func ValidExtension(path string) error {
	_, err := typeForPath(path)
	return err
}

// Write writes a proto message to a .textproto or .binproto file, based on the file extension.
// If the file name additionally has the .gz suffix, it's zipped before writing.
func Write(filePath string, outputProto proto.Message) error {
	ft, err := typeForPath(filePath)
	if err != nil {
		return err
	}
	return write(filePath, outputProto, ft)
}

// WriteWithFormat writes a proto message to a .textproto or .binproto file, based
// on the value of the format parameter ("textproto" or "binproto")
func WriteWithFormat(filePath string, outputProto proto.Message, format string) error {
	ft := &fileType{isGZipped: false, isBinProto: format == "binproto"}
	return write(filePath, outputProto, ft)
}

func write(filePath string, outputProto proto.Message, ft *fileType) error {
	var p []byte
	var err error
	if ft.isBinProto {
		if p, err = proto.Marshal(outputProto); err != nil {
			return err
		}
	} else {
		opts := prototext.MarshalOptions{Multiline: true}
		if p, err = (opts.Marshal(outputProto)); err != nil {
			return err
		}
	}

	log.Infof("Marshaled result proto has %d bytes", len(p))

	f, err := os.Create(filePath)
	if err != nil {
		return err
	}
	defer f.Close()
	if ft.isGZipped {
		writer := gzip.NewWriter(f)
		if _, err := writer.Write(p); err != nil {
			return err
		}
		if err := writer.Close(); err != nil {
			return err
		}
	} else if _, err := f.Write(p); err != nil {
		return err
	}
	return nil
}
