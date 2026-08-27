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

package spdx

// SPDX 3.0.1 element types, as serialized in the JSON-LD "type" field.
const (
	TypeCreationInfo       = "CreationInfo"
	TypeSpdxDocument       = "SpdxDocument"
	TypeRelationship       = "Relationship"
	TypePerson             = "Person"
	TypeOrganization       = "Organization"
	TypeTool               = "Tool"
	TypeSoftwareAgent      = "SoftwareAgent"
	TypePackage            = "software_Package"
	TypeFile               = "software_File"
	TypeLicenseExpression  = "simplelicensing_LicenseExpression"
	TypeCustomLicense      = "expandedlicensing_CustomLicense"
	TypeHash               = "Hash"
	TypeExternalIdentifier = "ExternalIdentifier"
	TypeDictionaryEntry    = "DictionaryEntry"
)

// SPDX 3.0.1 RelationshipType vocabulary entries used by the converter.
const (
	RelDescribes             = "describes"
	RelContains              = "contains"
	RelDependsOn             = "dependsOn"
	RelHasDependencyManifest = "hasDependencyManifest"
	RelDescendantOf          = "descendantOf"
	RelHasConcludedLicense   = "hasConcludedLicense"
)

const (
	// SPDX3Context is the JSON-LD context every SPDX 3.0.1 serialization must reference.
	SPDX3Context = "https://spdx.org/rdf/3.0.1/spdx-context.jsonld"
	// SPDX3Version is the value of CreationInfo.specVersion.
	SPDX3Version = "3.0.1"
	// creationInfoID is the blank node all elements point their creationInfo at.
	creationInfoID = "_:creationInfo_0"
)

// Document3 is the top level of an SPDX 3.0.1 JSON-LD serialization.
type Document3 struct {
	Context string `json:"@context"`
	Graph   []any  `json:"@graph"`
}

// CreationInfo3 records who and what produced the elements referencing it. Unlike every other
// element it is a blank node rather than an IRI-identified Element.
type CreationInfo3 struct {
	ID           string   `json:"@id"`
	Type         string   `json:"type"`
	SpecVersion  string   `json:"specVersion"`
	Created      string   `json:"created"`
	CreatedBy    []string `json:"createdBy"`
	CreatedUsing []string `json:"createdUsing,omitempty"`
}

// Element3 holds the Core profile fields shared by every SPDX 3.0.1 Element. It is embedded by the
// concrete element types, and used directly for the Agent types, which add nothing to it.
type Element3 struct {
	SPDXID             string                `json:"spdxId"`
	Type               string                `json:"type"`
	Name               string                `json:"name,omitempty"`
	Summary            string                `json:"summary,omitempty"`
	Description        string                `json:"description,omitempty"`
	ExternalIdentifier []ExternalIdentifier3 `json:"externalIdentifier,omitempty"`
	VerifiedUsing      []Hash3               `json:"verifiedUsing,omitempty"`
	CreationInfo       string                `json:"creationInfo,omitempty"`
}

// SpdxDocument3 is the single document element of the serialization.
type SpdxDocument3 struct {
	Element3
	DataLicense        string   `json:"dataLicense,omitempty"`
	RootElement        []string `json:"rootElement,omitempty"`
	ProfileConformance []string `json:"profileConformance,omitempty"`
}

// Package3 is a Software profile Package.
type Package3 struct {
	Element3
	PackageVersion   string `json:"software_packageVersion,omitempty"`
	PackageURL       string `json:"software_packageUrl,omitempty"`
	DownloadLocation string `json:"software_downloadLocation,omitempty"`
	SourceInfo       string `json:"software_sourceInfo,omitempty"`
}

// File3 is a Software profile File.
type File3 struct {
	Element3
	CopyrightText string `json:"software_copyrightText,omitempty"`
}

// Relationship3 is a directed edge between elements. SPDX 3.0.1 replaces 2.3's RefA/RefB pair with
// a single "from" and a list of "to".
type Relationship3 struct {
	Element3
	From             string   `json:"from"`
	To               []string `json:"to"`
	RelationshipType string   `json:"relationshipType"`
}

// LicenseExpression3 wraps an SPDX license expression string as a referenceable element.
// CustomIDToURI resolves any LicenseRef- id appearing in the expression to the CustomLicense
// element carrying its text.
type LicenseExpression3 struct {
	Element3
	LicenseExpression string             `json:"simplelicensing_licenseExpression"`
	CustomIDToURI     []DictionaryEntry3 `json:"simplelicensing_customIdToUri,omitempty"`
}

// DictionaryEntry3 is a key/value pair used by map-valued properties.
type DictionaryEntry3 struct {
	Type  string `json:"type"`
	Key   string `json:"key"`
	Value string `json:"value"`
}

// CustomLicense3 carries the text of a license that isn't on the SPDX license list. It replaces
// 2.3's document level OtherLicenses list.
type CustomLicense3 struct {
	Element3
	LicenseText string `json:"simplelicensing_licenseText"`
}

// Hash3 is an IntegrityMethod holding a single digest.
type Hash3 struct {
	Type      string `json:"type"`
	Algorithm string `json:"algorithm"`
	HashValue string `json:"hashValue"`
}

// ExternalIdentifier3 associates an element with an identifier from an external namespace such as
// purl or CPE.
type ExternalIdentifier3 struct {
	Type                   string `json:"type"`
	ExternalIdentifierType string `json:"externalIdentifierType"`
	Identifier             string `json:"identifier"`
}
