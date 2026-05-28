package androidapk

import (
	"strings"

	"github.com/google/osv-scalibr/extractor"
	androidmeta "github.com/google/osv-scalibr/extractor/filesystem/embeddedfs/androidapk/metadata"
	"github.com/google/osv-scalibr/purl"
)

// artifactIDMapping contains known mappings for Google Services modules
// Key: cleaned short name (e.g. "basement"), Value: full Maven artifact ID
// Reference:
// https://mvnrepository.com/artifact/com.google.android.gms
var artifactIDMapping = map[string]map[string]string{
	"com.google.android.gms": {
		"basement":       "play-services-basement",
		"ads":            "play-services-ads",
		"adsidentifier":  "play-services-ads-identifier",
		"auth":           "play-services-auth",
		"auth_api_phone": "play-services-auth-api-phone",
		"base":           "play-services-base",
		"cast":           "play-services-cast",
		"core":           "play-services-core",
		"fitness":        "play-services-fitness",
		"games":          "play-services-games",
		"location":       "play-services-location",
		"maps":           "play-services-maps",
		"nearby":         "play-services-nearby",
		"pay":            "play-services-pay",
		"wallet":         "play-services-wallet",
		"vision":         "play-services-vision",
		"mlkit":          "play-services-mlkit-text-recognition",
		"tapandpay":      "play-services-tapandpay",
		"wearable":       "play-services-wearable",
		"phenotype":      "play-services-phenotype",
		"measurement":    "play-services-measurement",
	},

	"com.google.firebase": {
		"auth":                   "firebase-auth",
		"database":               "firebase-database",
		"dynamic_links":          "firebase-dynamic-links",
		"firebase_auth":          "firebase-auth",
		"firebase_database":      "firebase-database",
		"firebase_dynamic_links": "firebase-dynamic-links",
	},
}

// extractInventoryFromManifest extracts Maven-like packages from <attribution> tags
func extractInventoryFromManifest(manifest *manifest, apkPath string) []*extractor.Package {
	var pkgs []*extractor.Package

	allMetadata := collectAllMetadata(manifest)

	for _, attr := range manifest.Attributions {
		if attr.Tag == "" {
			continue
		}

		version := resolveAttributionVersion(allMetadata, attr.Tag)
		if version == "" {
			continue
		}

		cleanedArtifact := cleanArtifactID(attr.Tag, manifest.Package)
		if cleanedArtifact == "" {
			continue
		}

		finalArtifactID := cleanedArtifact

		// Derive proper GroupID by removing the artifact part from the full tag
		groupID := deriveGroupID(attr.Tag, finalArtifactID, manifest)

		// Apply special mapping if this is a known special group
		if groupMappings, ok := artifactIDMapping[groupID]; ok {
			if mapped, ok := groupMappings[cleanedArtifact]; ok {
				finalArtifactID = mapped
			}
		}

		pkg := &extractor.Package{
			Name:     attr.Tag, // Full tag as human-readable name
			Version:  version,
			PURLType: purl.TypeMaven,
			Location: extractor.LocationFromPath(apkPath),
			Metadata: &androidmeta.Metadata{
				GroupID:    groupID,
				ArtifactID: finalArtifactID,
			},
		}
		pkgs = append(pkgs, pkg)
	}

	return pkgs
}

// resolveAttributionVersion finds the best version for a specific attribution tag.
// It prefers human-readable versions (e.g. "26.12.33") over raw build numbers.
func resolveAttributionVersion(metadata []metaData, tag string) string {
	version := findVersionInMetadata(metadata, tag)
	if version != "" {
		return normalizeVersion(version)
	}
	return ""
}

// normalizeVersion cleans up version strings, especially long numeric build numbers
func normalizeVersion(v string) string {
	v = strings.TrimSpace(v)
	if v == "" {
		return ""
	}

	// If it's a long numeric string (like versionCode 261233000), try to format it nicely
	if isNumericBuildNumber(v) {
		return formatNumericVersion(v)
	}

	// Otherwise return as-is (e.g. "26.12.33")
	return v
}

// isNumericBuildNumber returns true for long strings that are purely numeric
func isNumericBuildNumber(v string) bool {
	if len(v) < 7 {
		return false // short numbers are likely intentional
	}
	for _, r := range v {
		if r < '0' || r > '9' {
			return false
		}
	}
	return true
}

// formatNumericVersion attempts to convert long version codes into readable format
// Example: "261233000" -> "26.12.33"
func formatNumericVersion(v string) string {
	// Common Google version code pattern: major + minor + patch + build
	switch len(v) {
	case 9: // e.g. 261233000
		major := v[0:2]
		minor := v[2:4]
		patch := v[4:6]
		return major + "." + minor + "." + patch
	case 8, 10, 11:
		// Try to insert dots every 2-3 digits from the left
		var parts []string
		for i := 0; i < len(v); i += 2 {
			end := min(i+2, len(v))
			parts = append(parts, v[i:end])
		}
		return strings.Join(parts, ".")
	}

	// Fallback: return original if we can't make it nicer
	return v
}

// collectAllMetadata gathers metadata from Application and all its components
func collectAllMetadata(manifest *manifest) []metaData {
	var all []metaData

	// Application level
	all = append(all, manifest.Application.MetaData...)

	// Activities
	for _, a := range manifest.Application.Activities {
		all = append(all, a.MetaData...)
	}

	// Activity Aliases
	for _, a := range manifest.Application.ActivityAliases {
		all = append(all, a.MetaData...)
	}

	// Services
	for _, s := range manifest.Application.Services {
		all = append(all, s.MetaData...)
	}

	// Providers
	for _, p := range manifest.Application.Providers {
		all = append(all, p.MetaData...)
	}

	return all
}

// findVersionInMetadata looks for version-related metadata keys for a given attribution tag
func findVersionInMetadata(metadata []metaData, tag string) string {
	prefixes := []string{
		tag + ".version",
		tag + ".VERSION",
		tag + ".sdkversion",
		tag + ".SDK_VERSION",
		strings.ToLower(tag) + ".version",
	}

	for _, md := range metadata {
		if md.Name == "" || md.Value == "" {
			continue
		}

		nameLower := strings.ToLower(md.Name)

		for _, prefix := range prefixes {
			if strings.EqualFold(md.Name, prefix) || strings.HasSuffix(nameLower, ".version") {
				// Also check if the metadata name contains the tag
				if strings.Contains(strings.ToLower(md.Name), strings.ToLower(tag)) {
					return md.Value
				}
			}
		}
	}
	return ""
}

// deriveGroupID constructs the Maven Group ID by removing the artifact ID from the full tag
// Example: "com.google.android.gms.ads" with artifact "play-services-ads" to "com.google.android.gms"
func deriveGroupID(tag, artifactID string, manifest *manifest) string {
	if artifactID == "" {
		return tag
	}

	// Try removing with dot prefix
	cleaned := strings.TrimSuffix(tag, "."+artifactID)
	cleaned = strings.Trim(cleaned, ".")

	if cleaned != "" {
		return cleaned
	}

	// Fallback: use original manifest package
	return manifest.Package
}

// cleanArtifactID removes the group prefix and cleans the artifact name
func cleanArtifactID(tag, pkg string) string {
	// Remove leading and trailing "."
	tag = strings.Trim(tag, ".")

	if strings.HasPrefix(tag, pkg) {
		artifact := strings.TrimPrefix(tag, pkg+".")
		artifact = strings.Trim(artifact, ".")
		return artifact
	}

	// Fallback: keep only the last segment
	if idx := strings.LastIndex(tag, "."); idx != -1 {
		tag = tag[idx+1:]
	}

	tag = strings.Trim(tag, ".")
	return tag
}
