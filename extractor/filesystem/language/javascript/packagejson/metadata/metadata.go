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

// Package metadata defines a metadata struct for Javascript packages.
package metadata

import (
	"encoding/json"
	"fmt"
	"regexp"
	"strings"

	"github.com/google/osv-scalibr/extractor/filesystem/internal"

	pb "github.com/google/osv-scalibr/binary/proto/scan_result_go_proto"
)

// Person represents a person field in a javascript package.json file.
type Person struct {
	Name  string `json:"name"`
	Email string `json:"email"`
	URL   string `json:"url"`
}

// NPMPackageSource is the source of the NPM package.
type NPMPackageSource string

const (
	// Unknown is when the source of the NPM package is unknown because the lockfile was not found.
	Unknown NPMPackageSource = "UNKNOWN"
	// PublicRegistry is the public NPM registry.
	PublicRegistry NPMPackageSource = "PUBLIC_REGISTRY"
	// Other is any other remote or private source (e.g. Github).
	// This is used for packages that are not found in the public NPM registry.
	Other NPMPackageSource = "OTHER"
	// Local is the local filesystem that stores the package versions.
	// This is used for when the package is locally-developed or -installed.
	Local NPMPackageSource = "LOCAL"
)

// match example: "author": "Isaac Z. Schlueter <i@izs.me> (http://blog.izs.me)"
// ---> name: "Isaac Z. Schlueter" email: "i@izs.me" url: "http://blog.izs.me"
var personPattern = regexp.MustCompile(`^\s*(?P<name>[^<(]*)(\s+<(?P<email>.*)>)?(\s\((?P<url>.*)\))?\s*$`)

// UnmarshalJSON parses a JSON object or string into a Person struct.
func (p *Person) UnmarshalJSON(b []byte) error {
	var personStr string
	var fields map[string]string

	if err := json.Unmarshal(b, &personStr); err != nil {
		// string parsing did not work, assume a map was given
		// for more information: https://docs.npmjs.com/files/package.json#people-fields-author-contributors
		var rawJSON map[string]any
		if err := json.Unmarshal(b, &rawJSON); err != nil {
			return fmt.Errorf("unable to parse package.json person: %w", err)
		}
		fields = rawToPerson(rawJSON)
	} else {
		// parse out "name <email> (url)" into a person struct
		fields = internal.MatchNamedCaptureGroups(personPattern, personStr)
	}

	if _, ok := fields["name"]; ok {
		// translate the map into a structure
		*p = Person{
			Name:  fields["name"],
			Email: fields["email"],
			URL:   fields["url"],
		}
	}

	return nil
}

// PersonString produces a string format of Person struct in the format of "name <email> (url)"
func (p *Person) PersonString() string {
	if p == nil || p.Name == "" {
		return ""
	}
	result := p.Name
	if p.Email != "" {
		result += fmt.Sprintf(" <%s>", p.Email)
	}
	if p.URL != "" {
		result += fmt.Sprintf(" (%s)", p.URL)
	}
	return result
}

// PersonFromString parses a string of the form "name <email> (url)" into a Person struct.
func PersonFromString(s string) *Person {
	if s == "" {
		return nil
	}
	fields := internal.MatchNamedCaptureGroups(personPattern, s)
	for name, field := range fields {
		fields[name] = strings.TrimSpace(field)
	}
	return &Person{
		Name:  fields["name"],
		Email: fields["email"],
		URL:   fields["url"],
	}
}

// JavascriptPackageJSONMetadata holds parsing information for a javascript package.json file.
type JavascriptPackageJSONMetadata struct {
	Author       *Person   `json:"author"`
	Maintainers  []*Person `json:"maintainers"`
	Contributors []*Person `json:"contributors"`

	// FromNPMRepository field is annotated by the misc/from-npm annotator by parsing the lockfile
	// of the root-level directory. This field is used to indicate whether this package's dependency
	// was resolved from the official NPM registry during installation. If false, it means the package
	// was either installed from a local path, a git repository, or another private registry.
	// This is to identify name collisions between locally published packages and official NPM packages.
	Source NPMPackageSource
}

// SetProto sets the JavascriptMetadata field in the Package proto.
func (m *JavascriptPackageJSONMetadata) SetProto(p *pb.Package) {
	if m == nil {
		return
	}
	if p == nil {
		return
	}

	p.Metadata = &pb.Package_JavascriptMetadata{
		JavascriptMetadata: &pb.JavascriptPackageJSONMetadata{
			Author:       m.Author.PersonString(),
			Contributors: personsToProto(m.Contributors),
			Maintainers:  personsToProto(m.Maintainers),
			Source:       m.Source.ToProto(),
		},
	}
}

// ToStruct converts the JavascriptPackageJSONMetadata proto to a Metadata struct.
func ToStruct(m *pb.JavascriptPackageJSONMetadata) *JavascriptPackageJSONMetadata {
	if m == nil {
		return nil
	}

	var author *Person
	if m.GetAuthor() != "" {
		author = PersonFromString(m.GetAuthor())
	}

	return &JavascriptPackageJSONMetadata{
		Author:       author,
		Maintainers:  personsToStruct(m.GetMaintainers()),
		Contributors: personsToStruct(m.GetContributors()),
		Source:       packageSourceToStruct(m.GetSource()),
	}
}

// ToProto converts the NPMPackageSource to the proto enum.
func (source NPMPackageSource) ToProto() pb.PackageSource {
	switch source {
	case PublicRegistry:
		return pb.PackageSource_PUBLIC_REGISTRY
	case Local:
		return pb.PackageSource_LOCAL
	case Other:
		return pb.PackageSource_OTHER
	default:
		return pb.PackageSource_UNKNOWN
	}
}

func packageSourceToStruct(ps pb.PackageSource) NPMPackageSource {
	switch ps {
	case pb.PackageSource_PUBLIC_REGISTRY:
		return PublicRegistry
	case pb.PackageSource_OTHER:
		return Other
	case pb.PackageSource_LOCAL:
		return Local
	default:
		return Unknown
	}
}

func personsToProto(persons []*Person) []string {
	var personStrings []string
	for _, p := range persons {
		personStrings = append(personStrings, p.PersonString())
	}
	return personStrings
}

func personsToStruct(personStrings []string) []*Person {
	var persons []*Person
	for _, s := range personStrings {
		persons = append(persons, PersonFromString(s))
	}
	return persons
}

func rawToPerson(rawJSON map[string]any) map[string]string {
	personMap := make(map[string]string)
	for key := range rawJSON {
		if val, ok := rawJSON[key].(string); ok {
			personMap[key] = val
		}
	}
	return personMap
}
