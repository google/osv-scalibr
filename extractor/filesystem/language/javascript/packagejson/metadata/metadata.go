// Copyright 2026 Google LLC
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

// Package metadata defines aliases for backward compatibility with javascript/metadata.
package metadata

import (
	jsmeta "github.com/google/osv-scalibr/extractor/filesystem/language/javascript/metadata"
)

type (
	// Person represents a person field in a javascript package.json file.
	Person = jsmeta.Person
	// NPMPackageSource is the source of the NPM package.
	NPMPackageSource = jsmeta.NPMPackageSource
	// JavascriptPackageJSONMetadata is an alias for JavascriptPackageMetadata.
	JavascriptPackageJSONMetadata = jsmeta.JavascriptPackageMetadata
)

const (
	// Unknown is when the source of the NPM package is unknown because the lockfile was not found.
	Unknown = jsmeta.Unknown
	// PublicRegistry is the public NPM registry.
	PublicRegistry = jsmeta.PublicRegistry
	// Other is any other remote or private source (e.g. GitHub).
	Other = jsmeta.Other
	// Local is the local filesystem that stores the package versions.
	Local = jsmeta.Local
)

var (
	// PersonFromString parses a string of the form "name <email> (url)" into a Person struct.
	PersonFromString = jsmeta.PersonFromString
	// ToProto converts JavascriptPackageJSONMetadata to proto.
	ToProto = jsmeta.ToProto
	// ToStruct converts proto to JavascriptPackageJSONMetadata.
	ToStruct = jsmeta.ToStruct
)
