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
	spb "github.com/google/osv-scalibr/binary/proto/scan_result_go_proto"
	"github.com/google/osv-scalibr/extractor"
)

var (
	// Same maps for the legacy annotation fields.
	// TODO(b/400910349): Remove once integrators stop using the legacy field.
	structToProtoAnnotations = map[extractor.Annotation]spb.Package_AnnotationEnum{
		extractor.Unknown:         spb.Package_UNSPECIFIED,
		extractor.Transitional:    spb.Package_TRANSITIONAL,
		extractor.InsideOSPackage: spb.Package_INSIDE_OS_PACKAGE,
		extractor.InsideCacheDir:  spb.Package_INSIDE_CACHE_DIR,
	}
	protoToStructAnnotations = func() map[spb.Package_AnnotationEnum]extractor.Annotation {
		m := make(map[spb.Package_AnnotationEnum]extractor.Annotation)
		for k, v := range structToProtoAnnotations {
			m[v] = k
		}
		if len(m) != len(structToProtoAnnotations) {
			panic("protoToStructAnnotations does not contain all values from structToProtoAnnotations")
		}
		return m
	}()
)

// --- Struct to Proto

// AnnotationToProto converts an extractor.Annotation to a Package_AnnotationEnum.
func AnnotationToProto(a extractor.Annotation) spb.Package_AnnotationEnum {
	return structToProtoAnnotations[a]
}

// --- Proto to Struct

// AnnotationToStruct converts a Package_AnnotationEnum to an extractor.Annotation.
func AnnotationToStruct(a spb.Package_AnnotationEnum) extractor.Annotation {
	return protoToStructAnnotations[a]
}
