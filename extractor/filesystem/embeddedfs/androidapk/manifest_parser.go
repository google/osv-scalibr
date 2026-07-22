package androidapk

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"

	"github.com/shogo82148/androidbinary"
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

// loadManifest loads AndroidManifest.xml from an unpacked APK directory,
// resolves resource references using resources.arsc (if present),
// decodes it into our manifest structure,
// and returns both the parsed manifest and normalized XML bytes.
func loadManifest(root *os.Root) (*manifest, []byte, error) {
	xmlData, err := root.ReadFile("AndroidManifest.xml")
	if err != nil {
		return nil, nil, fmt.Errorf("read AndroidManifest.xml: %w", err)
	}

	xmlFile, err := androidbinary.NewXMLFile(bytes.NewReader(xmlData))
	if err != nil {
		return nil, nil, fmt.Errorf("parse binary AndroidManifest.xml: %w", err)
	}

	var resTable *androidbinary.TableFile

	if _, err := root.Stat("resources.arsc"); err == nil {
		resData, err := root.ReadFile("resources.arsc")
		if err != nil {
			return nil, nil, fmt.Errorf("read resources.arsc: %w", err)
		}

		resTable, err = androidbinary.NewTableFile(bytes.NewReader(resData))
		if err != nil {
			return nil, nil, fmt.Errorf("parse resources.arsc: %w", err)
		}
	}

	var manifest manifest
	if err := xmlFile.Decode(&manifest, resTable, nil); err != nil {
		return nil, nil, fmt.Errorf("decode AndroidManifest.xml: %w", err)
	}

	normalizedXML, err := io.ReadAll(xmlFile.Reader())
	if err != nil {
		return nil, nil, fmt.Errorf("read normalized manifest: %w", err)
	}

	return &manifest, normalizedXML, nil
}

// dumpManifest writes the normalized Android manifest to disk.
func dumpManifest(manifest []byte, root *os.Root) error {
	if len(manifest) == 0 {
		return errors.New("manifest is empty")
	}

	f, err := root.Create("AndroidManifest.normalized.xml")
	if err != nil {
		return fmt.Errorf("failed to create normalized manifest: %w", err)
	}
	defer f.Close()

	if _, err := f.Write(manifest); err != nil {
		return fmt.Errorf("failed to write normalized manifest: %w", err)
	}

	return nil
}
