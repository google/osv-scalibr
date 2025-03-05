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

package packagejson

import (
	"encoding/json"
	"fmt"
	"regexp"

	"github.com/google/osv-scalibr/extractor/filesystem/internal"
)

// Person represents a person field in a javascript package.json file.
type Person struct {
	Name  string `json:"name"`
	Email string `json:"email"`
	URL   string `json:"url"`
}

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

// JavascriptPackageJSONMetadata holds parsing information for a javascript package.json file.
type JavascriptPackageJSONMetadata struct {
	Author       *Person   `json:"author"`
	Maintainers  []*Person `json:"maintainers"`
	Contributors []*Person `json:"contributors"`
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
