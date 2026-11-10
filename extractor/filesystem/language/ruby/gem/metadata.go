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

package gem

import (
	"strings"

	"github.com/google/osv-scalibr/binary/proto/metadata"
	pb "github.com/google/osv-scalibr/binary/proto/scan_result_go_proto"
	"github.com/google/osv-scalibr/semantic"
	"gopkg.in/yaml.v3"
)

func init() {
	metadata.Register(ToStruct, ToProto)
}

// RubyGemMetadata contains metadata fields extracted from a Ruby gem specification.
type RubyGemMetadata struct {
	Authors      []string      `json:"authors,omitempty"`
	Description  string        `json:"description,omitempty"`
	Homepage     string        `json:"homepage,omitempty"`
	Licenses     []string      `json:"licenses,omitempty"`
	Dependencies []*Dependency `json:"dependencies,omitempty"`
	Platform     string        `json:"platform,omitempty"`
	Summary      string        `json:"summary,omitempty"`
}

// IsProtoable marks the struct as a metadata type.
func (m *RubyGemMetadata) IsProtoable() {}

// ToProto converts RubyGemMetadata struct to RubyGemMetadata proto.
func ToProto(m *RubyGemMetadata) *pb.RubyGemMetadata {
	if m == nil {
		return nil
	}
	var deps []*pb.RubyGemMetadata_Dependency
	if m.Dependencies != nil {
		deps = make([]*pb.RubyGemMetadata_Dependency, 0, len(m.Dependencies))
		for _, d := range m.Dependencies {
			if d == nil {
				continue
			}
			var reqs []*pb.RubyGemMetadata_Dependency_RequirementConstraint
			for _, r := range d.Requirements() {
				reqs = append(reqs, &pb.RubyGemMetadata_Dependency_RequirementConstraint{
					Operator: r.Operator,
					Version:  r.Version,
				})
			}
			deps = append(deps, &pb.RubyGemMetadata_Dependency{
				Name:         d.Name,
				Type:         d.Type,
				Requirements: reqs,
				Prerelease:   d.Prerelease,
			})
		}
	}
	return &pb.RubyGemMetadata{
		Authors:      m.Authors,
		Description:  m.Description,
		Homepage:     m.Homepage,
		Licenses:     m.Licenses,
		Dependencies: deps,
		Platform:     m.Platform,
		Summary:      m.Summary,
	}
}

// ToStruct converts RubyGemMetadata proto to RubyGemMetadata struct.
func ToStruct(p *pb.RubyGemMetadata) *RubyGemMetadata {
	if p == nil {
		return nil
	}
	var deps []*Dependency
	if p.GetDependencies() != nil {
		deps = make([]*Dependency, 0, len(p.GetDependencies()))
		for _, d := range p.GetDependencies() {
			if d == nil {
				continue
			}
			var reqs []RequirementConstraint
			for _, r := range d.GetRequirements() {
				reqs = append(reqs, RequirementConstraint{
					Operator: r.GetOperator(),
					Version:  r.GetVersion(),
				})
			}
			var req *Requirement
			if len(reqs) > 0 {
				req = &Requirement{Requirements: reqs}
			}
			deps = append(deps, &Dependency{
				Name:        d.GetName(),
				Type:        d.GetType(),
				Requirement: req,
				Prerelease:  d.GetPrerelease(),
			})
		}
	}
	return &RubyGemMetadata{
		Authors:      p.GetAuthors(),
		Description:  p.GetDescription(),
		Homepage:     p.GetHomepage(),
		Licenses:     p.GetLicenses(),
		Dependencies: deps,
		Platform:     p.GetPlatform(),
		Summary:      p.GetSummary(),
	}
}

// Dependency represents a dependency declared in a gem specification.
type Dependency struct {
	Name                string       `json:"name"                 yaml:"name"`
	Type                string       `json:"type"                 yaml:"type"`
	Requirement         *Requirement `json:"requirement"          yaml:"requirement"`
	VersionRequirements *Requirement `json:"version_requirements" yaml:"version_requirements"`
	Prerelease          bool         `json:"prerelease"           yaml:"prerelease"`
}

// IsRuntime returns true if the dependency is a runtime dependency.
func (d *Dependency) IsRuntime() bool {
	if d == nil {
		return false
	}
	// Default to assuming it is a runtime dependency if the type is not specified.
	if d.Type == "" {
		return true
	}
	t := strings.TrimSpace(d.Type)
	t = strings.TrimPrefix(t, ":")
	return t == "runtime"
}

// Requirements returns the slice of requirement constraints.
func (d *Dependency) Requirements() []RequirementConstraint {
	if d == nil {
		return nil
	}
	if d.Requirement != nil && len(d.Requirement.Requirements) > 0 {
		return d.Requirement.Requirements
	}
	if d.VersionRequirements != nil && len(d.VersionRequirements.Requirements) > 0 {
		return d.VersionRequirements.Requirements
	}
	return nil
}

// Requirement holds a list of requirement constraints.
type Requirement struct {
	Requirements []RequirementConstraint `json:"requirements" yaml:"requirements"`
}

// RequirementConstraint represents an individual [operator, version] pair.
type RequirementConstraint struct {
	Operator string `json:"operator"`
	Version  string `json:"version"`
}

// UnmarshalYAML unmarshals a [operator, version] sequence node from YAML.
// In RubyGems metadata, each dependency requirement is serialized as a two-element
// sequence: [operator, version].
// The version element can appear in two distinct shapes:
//  1. Ruby Object Mapping (!ruby/object:Gem::Version):
//     Standard format produced by Psych (Ruby's YAML serializer). The AST node is a
//     yaml.MappingNode with child keys, where the version string lives under the
//     "version" key (e.g. version: '2.0'). The node's top-level Value string is empty.
//  2. Plain Scalar String:
//     Alternative/legacy format or simplified YAML where the version is a direct scalar
//     string (e.g. '2.0'). The AST node is a yaml.ScalarNode.
//
// We decode using gemVersionWrapper, which handles both mapping nodes and scalar nodes.
func (c *RequirementConstraint) UnmarshalYAML(value *yaml.Node) error {
	if value.Kind != yaml.SequenceNode || len(value.Content) < 2 {
		return nil
	}
	c.Operator = strings.TrimSpace(value.Content[0].Value)
	var gv gemVersionWrapper
	_ = value.Content[1].Decode(&gv)
	c.Version = strings.TrimSpace(string(gv))
	return nil
}

// gemVersionWrapper decodes a version string from either:
// - A yaml.ScalarNode (e.g., "1.2.3")
// - A yaml.MappingNode representing a !ruby/object:Gem::Version (e.g., {version: "1.2.3"})
type gemVersionWrapper string

// UnmarshalYAML decodes scalar versions or !ruby/object:Gem::Version mapping nodes.
func (gv *gemVersionWrapper) UnmarshalYAML(value *yaml.Node) error {
	// Case 1: Plain scalar version (e.g. "1.2.3" or '2.0').
	// The version string is stored directly in the AST node's Value field.
	if value.Kind == yaml.ScalarNode {
		*gv = gemVersionWrapper(value.Value)
		return nil
	}

	// Case 2: Serialized Ruby Gem::Version object (!ruby/object:Gem::Version).
	// In go-yaml, a MappingNode stores its key/value pairs sequentially in Content:
	// Content[0] = key0, Content[1] = val0, Content[2] = key1, Content[3] = val1, etc.
	// We scan the keys with a step of 2 to locate the "version" attribute and extract
	// its associated value node.
	if value.Kind == yaml.MappingNode {
		for i := 0; i < len(value.Content)-1; i += 2 {
			if value.Content[i].Value == "version" {
				*gv = gemVersionWrapper(value.Content[i+1].Value)
				return nil
			}
		}
	}
	return nil
}

// gemSpecification represents the YAML schema of Gem::Specification in metadata.gz.
type gemSpecification struct {
	Name         string            `yaml:"name"`
	Version      gemVersionWrapper `yaml:"version"`
	Platform     string            `yaml:"platform"`
	Authors      []string          `yaml:"authors"`
	Description  string            `yaml:"description"`
	Homepage     string            `yaml:"homepage"`
	Licenses     []string          `yaml:"licenses"`
	Summary      string            `yaml:"summary"`
	Dependencies []*Dependency     `yaml:"dependencies"`
}

// ResolveDependencyVersion extracts the minimum lower-bound version from a list of constraints.
// It considers constraints with "=", ">=", and "~>".
// For "~> x", the version is normalized to "x.0.0".
// For "~> x.y", the version is normalized to "x.y.0".
// For "~> x.y.z", the version is kept as "x.y.z".
// If multiple qualifying lower-bound constraints exist, the highest version is selected.
// Returns (version, true) if a valid lower bound is found, or ("", false) if none exist.
func ResolveDependencyVersion(reqs []RequirementConstraint) (string, bool) {
	var bestVersion string
	var bestParsed semantic.RubyGemsVersion
	found := false

	for _, req := range reqs {
		op := strings.TrimSpace(req.Operator)
		ver := strings.TrimSpace(req.Version)
		if ver == "" {
			continue
		}

		var candidate string
		switch op {
		case "=", ">=":
			candidate = ver
		case "~>":
			candidate = NormalizeTwiddleWakka(ver)
		default:
			// Ignore other operators like "<", "<=", "!=", etc.
			continue
		}

		parsed := semantic.ParseRubyGemsVersion(candidate)
		if !found {
			bestVersion = candidate
			bestParsed = parsed
			found = true
			continue
		}

		cmp, err := parsed.Compare(bestParsed)
		if err == nil && cmp > 0 {
			bestVersion = candidate
			bestParsed = parsed
		}
	}

	return bestVersion, found
}

// NormalizeTwiddleWakka normalizes a version constraint for the pessimistic operator (~>).
// - "x" -> "x.0.0"
// - "x.y" -> "x.y.0"
// - "x.y.z" or more -> "x.y.z..."
func NormalizeTwiddleWakka(v string) string {
	parts := strings.Split(v, ".")
	switch len(parts) {
	case 1:
		return parts[0] + ".0.0"
	case 2:
		return parts[0] + "." + parts[1] + ".0"
	default:
		return v
	}
}
