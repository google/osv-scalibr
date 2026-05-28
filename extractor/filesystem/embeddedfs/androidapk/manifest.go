package androidapk

import (
	"encoding/xml"
	"errors"
	"fmt"
	"os"
	"path/filepath"
)

// manifest represents the AndroidManifest.xml root <manifest> element
// Although the structure below only contains enteries that are used in this plugin, it can be scaled if needed.
// Reference:
// https://developer.android.com/guide/topics/manifest/manifest-intro
type manifest struct {
	Package      string        `xml:"package,attr"`
	Attributions []attribution `xml:"attribution"`
	Application  application   `xml:"application"`
}

// attribution represents <attribution>
type attribution struct {
	Tag string `xml:"tag,attr"`
}

// application represents <application>
type application struct {
	Activities      []activity      `xml:"activity"`
	ActivityAliases []activityAlias `xml:"activity-alias"`
	Services        []service       `xml:"service"`
	Providers       []provider      `xml:"provider"`
	MetaData        []metaData      `xml:"meta-data"`
}

// activity represents <activity>
type activity struct {
	MetaData []metaData `xml:"meta-data"`
}

// activityAlias represents <activity-alias>
type activityAlias struct {
	MetaData []metaData `xml:"meta-data"`
}

// service represents <service>
type service struct {
	MetaData []metaData `xml:"meta-data"`
}

// provider represents <provider>
type provider struct {
	MetaData []metaData `xml:"meta-data"`
}

// metaData represents <meta-data>
type metaData struct {
	Name  string `xml:"http://schemas.android.com/apk/res/android name,attr"`
	Value string `xml:"value,attr"`
}

// ParseManifest parses the AndroidManifest.xml
func ParseManifest(data []byte) (*manifest, error) {
	var manifest manifest
	err := xml.Unmarshal(data, &manifest)
	if err != nil {
		return nil, err
	}
	return &manifest, nil
}

// DumpManifest writes the normalized Android manifest to disk.
func DumpManifest(manifest []byte, tempDir string) error {
	if len(manifest) == 0 {
		return errors.New("manifest is empty")
	}

	outputPath := filepath.Join(tempDir, "AndroidManifestNormalized.xml")
	if err := os.WriteFile(outputPath, manifest, 0644); err != nil {
		return fmt.Errorf("failed to write normalized manifest: %w", err)
	}

	return nil
}
