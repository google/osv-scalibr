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

// Package cli defines the structures to store the CLI flags used by the scanner binary.
package cli

import (
	"errors"
	"fmt"
	"os"
	"regexp"
	"slices"
	"strings"

	"github.com/gobwas/glob"
	"github.com/google/go-containerregistry/pkg/authn"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	scalibr "github.com/google/osv-scalibr"
	scalibrimage "github.com/google/osv-scalibr/artifact/image"
	"github.com/google/osv-scalibr/binary/cdx"
	"github.com/google/osv-scalibr/binary/platform"
	"github.com/google/osv-scalibr/binary/proto"
	binspdx "github.com/google/osv-scalibr/binary/spdx"
	"github.com/google/osv-scalibr/clients/resolution"
	"github.com/google/osv-scalibr/converter"
	convspdx "github.com/google/osv-scalibr/converter/spdx"
	"github.com/google/osv-scalibr/detector"
	"github.com/google/osv-scalibr/detector/govulncheck/binary"
	"github.com/google/osv-scalibr/enricher/transitivedependency/requirements"
	"github.com/google/osv-scalibr/extractor/filesystem"
	"github.com/google/osv-scalibr/extractor/filesystem/language/golang/gobinary"
	"github.com/google/osv-scalibr/extractor/filesystem/language/java/pomxmlnet"
	scalibrfs "github.com/google/osv-scalibr/fs"
	"github.com/google/osv-scalibr/log"
	"github.com/google/osv-scalibr/plugin"
	pl "github.com/google/osv-scalibr/plugin/list"
	"github.com/spdx/tools-golang/spdx/v2/common"
)

// Array is a type to be passed to flag.Var that supports arrays passed as repeated flags,
// e.g. ./scalibr -o binproto=out.bp -o spdx23-json=out.spdx.json
type Array []string

func (i *Array) String() string {
	return strings.Join(*i, ",")
}

// Set gets called whenever a new instance of a flag is read during CLI arg parsing.
// For example, in the case of -o foo -o bar the library will call arr.Set("foo") then arr.Set("bar").
func (i *Array) Set(value string) error {
	*i = append(*i, strings.TrimSpace(value))
	return nil
}

// Get returns the underlying []string value stored by this flag struct.
func (i *Array) Get() any {
	return i
}

// StringListFlag is a type to be passed to flag.Var that supports list flags passed as repeated
// flags, e.g. ./scalibr -o a -o b,c the library will call arr.Set("a") then arr.Set("a,b").
type StringListFlag struct {
	set          bool
	value        []string
	defaultValue []string
}

// NewStringListFlag creates a new StringListFlag with the given default value.
func NewStringListFlag(defaultValue []string) StringListFlag {
	return StringListFlag{defaultValue: defaultValue}
}

// Set gets called whenever a new instance of a flag is read during CLI arg parsing.
// For example, in the case of -o foo -o bar the library will call arr.Set("foo") then arr.Set("bar").
func (s *StringListFlag) Set(x string) error {
	s.value = append(s.value, strings.Split(x, ",")...)
	s.set = true
	return nil
}

// Get returns the underlying []string value stored by this flag struct.
func (s *StringListFlag) Get() any {
	return s.GetSlice()
}

// GetSlice returns the underlying []string value stored by this flag struct.
func (s *StringListFlag) GetSlice() []string {
	if s.set {
		return s.value
	}
	return s.defaultValue
}

func (s *StringListFlag) String() string {
	if len(s.value) == 0 {
		return ""
	}
	return fmt.Sprint(s.value)
}

// Reset resets the flag to its default value.
func (s *StringListFlag) Reset() {
	s.set = false
	s.value = nil
}

// Flags contains a field for all the cli flags that can be set.
type Flags struct {
	PrintVersion               bool
	Root                       string
	ResultFile                 string
	Output                     Array
	ExtractorsToRun            []string
	DetectorsToRun             []string
	AnnotatorsToRun            []string
	PluginsToRun               []string
	ExtractorOverride          Array
	PathsToExtract             []string
	IgnoreSubDirs              bool
	DirsToSkip                 []string
	SkipDirRegex               string
	SkipDirGlob                string
	MaxFileSize                int
	UseGitignore               bool
	RemoteImage                string
	ImageLocal                 string
	ImageTarball               string
	ImagePlatform              string
	GoBinaryVersionFromContent bool
	GovulncheckDBPath          string
	SPDXDocumentName           string
	SPDXDocumentNamespace      string
	SPDXCreators               string
	CDXComponentName           string
	CDXComponentType           string
	CDXComponentVersion        string
	CDXAuthors                 string
	Verbose                    bool
	ExplicitExtractors         bool
	FilterByCapabilities       bool
	StoreAbsolutePath          bool
	WindowsAllDrives           bool
	Offline                    bool
	LocalRegistry              string
}

var supportedOutputFormats = []string{
	"textproto", "binproto", "spdx23-tag-value", "spdx23-json", "spdx23-yaml", "cdx-json", "cdx-xml",
}

var supportedComponentTypes = []string{
	"application", "framework", "library", "container", "platform",
	"operating-system", "device", "device-driver", "firmware", "file",
	"machine-learning-model", "data", "cryptographic-asset",
}

// ValidateFlags validates the passed command line flags.
func ValidateFlags(flags *Flags) error {
	if flags.PrintVersion {
		// SCALIBR prints the version and exits so other flags don't need to be present.
		return nil
	}
	if len(flags.ResultFile) == 0 && len(flags.Output) == 0 {
		return errors.New("either --result or --o needs to be set")
	}
	if flags.Root != "" && flags.WindowsAllDrives {
		return errors.New("--root and --windows-all-drives cannot be used together")
	}
	if flags.ImagePlatform != "" && len(flags.RemoteImage) == 0 {
		return errors.New("--image-platform cannot be used without --remote-image")
	}
	if flags.ImageTarball != "" && flags.RemoteImage != "" {
		return errors.New("--image-tarball cannot be used with --remote-image")
	}
	if flags.ImageTarball != "" && flags.ImagePlatform != "" {
		return errors.New("--image-tarball cannot be used with --image-platform")
	}
	if flags.ImageLocal != "" && flags.RemoteImage != "" {
		return errors.New("image-local-docker cannot be used with --remote-image")
	}
	if flags.ImageLocal != "" && flags.ImagePlatform != "" {
		return errors.New("image-local-docker cannot be used with --image-platform")
	}
	if flags.ImageLocal != "" && flags.ImageTarball != "" {
		return errors.New("image-local-docker cannot be used with --image-tarball")
	}
	if err := validateResultPath(flags.ResultFile); err != nil {
		return fmt.Errorf("--result %w", err)
	}
	if err := validateOutput(flags.Output); err != nil {
		return fmt.Errorf("--o %w", err)
	}
	if err := validateExtractorOverride(flags.ExtractorOverride); err != nil {
		return fmt.Errorf("--extractor-override: %w", err)
	}
	if err := validateImagePlatform(flags.ImagePlatform); err != nil {
		return fmt.Errorf("--image-platform %w", err)
	}
	if err := validateMultiStringArg(flags.PluginsToRun); err != nil {
		return fmt.Errorf("--plugins: %w", err)
	}
	// Legacy args for setting plugins.
	if err := validateMultiStringArg(flags.ExtractorsToRun); err != nil {
		return fmt.Errorf("--extractors: %w", err)
	}
	if err := validateMultiStringArg(flags.DetectorsToRun); err != nil {
		return fmt.Errorf("--detectors: %w", err)
	}
	if err := validateMultiStringArg(flags.AnnotatorsToRun); err != nil {
		return fmt.Errorf("--annotators: %w", err)
	}

	if err := validateMultiStringArg(flags.DirsToSkip); err != nil {
		return fmt.Errorf("--skip-dirs: %w", err)
	}
	if err := validateRegex(flags.SkipDirRegex); err != nil {
		return fmt.Errorf("--skip-dir-regex: %w", err)
	}
	if err := validateGlob(flags.SkipDirGlob); err != nil {
		return fmt.Errorf("--skip-dir-glob: %w", err)
	}
	pluginsToRun := slices.Concat(flags.PluginsToRun, flags.ExtractorsToRun, flags.DetectorsToRun, flags.AnnotatorsToRun)
	if err := validateDependency(pluginsToRun, flags.ExplicitExtractors); err != nil {
		return err
	}
	if err := validateComponentType(flags.CDXComponentType); err != nil {
		return err
	}
	return nil
}

func validateExtractorOverride(extractorOverride []string) error {
	for _, item := range extractorOverride {
		parts := strings.SplitN(item, ":", 2)
		if len(parts) != 2 || parts[0] == "" || parts[1] == "" {
			return fmt.Errorf("invalid format for extractor override %q, should be <plugin-name>:<glob-pattern>", item)
		}
		if _, err := glob.Compile(parts[1]); err != nil {
			return fmt.Errorf("invalid glob pattern %q in extractor override %q: %w", parts[1], item, err)
		}
	}
	return nil
}

func validateResultPath(filePath string) error {
	if len(filePath) == 0 {
		return nil
	}
	if err := proto.ValidExtension(filePath); err != nil {
		return err
	}
	return nil
}

func validateOutput(output []string) error {
	for _, item := range output {
		o := strings.Split(item, "=")
		if len(o) != 2 {
			return errors.New("invalid output format, should follow a format like -o textproto=result.textproto -o spdx23-json=result.spdx.json")
		}
		oFormat := o[0]
		if !slices.Contains(supportedOutputFormats, oFormat) {
			return fmt.Errorf("output format %q not recognized, supported formats are %v", oFormat, supportedOutputFormats)
		}
	}
	return nil
}

func validateImagePlatform(imagePlatform string) error {
	if len(imagePlatform) == 0 {
		return nil
	}
	platformDetails := strings.Split(imagePlatform, "/")
	if len(platformDetails) < 2 {
		return fmt.Errorf("image platform '%s' is invalid. Must be in the form OS/Architecture (e.g. linux/amd64)", imagePlatform)
	}
	return nil
}

func validateMultiStringArg(arg []string) error {
	if len(arg) == 0 {
		return nil
	}
	for _, item := range arg {
		if len(item) == 0 {
			continue
		}
		for _, item := range strings.Split(item, ",") {
			if len(item) == 0 {
				return errors.New("list item cannot be left empty")
			}
		}
	}
	return nil
}

func validateRegex(arg string) error {
	if len(arg) == 0 {
		return nil
	}
	_, err := regexp.Compile(arg)
	return err
}

func validateGlob(arg string) error {
	_, err := glob.Compile(arg)
	return err
}

func validateDependency(pluginNames []string, requireExtractors bool) error {
	f := &Flags{PluginsToRun: pluginNames}
	plugins, err := f.pluginsToRun()
	if err != nil {
		return err
	}
	pMap := make(map[string]bool)
	for _, p := range plugins {
		pMap[p.Name()] = true
	}
	if requireExtractors {
		for _, p := range plugins {
			if d, ok := p.(detector.Detector); ok {
				for _, req := range d.RequiredExtractors() {
					if !pMap[req] {
						return fmt.Errorf("extractor %s must be turned on for Detector %s to run", req, d.Name())
					}
				}
			}
		}
	}
	return nil
}

func validateComponentType(componentType string) error {
	if len(componentType) > 0 && !slices.Contains(supportedComponentTypes, componentType) {
		return fmt.Errorf("unsupported cdx-component-type '%s'", componentType)
	}

	return nil
}

type extractorOverride struct {
	glob      glob.Glob
	extractor filesystem.Extractor
}

// GetScanConfig constructs a SCALIBR scan config from the provided CLI flags.
func (f *Flags) GetScanConfig() (*scalibr.ScanConfig, error) {
	plugins, err := f.pluginsToRun()
	if err != nil {
		return nil, err
	}
	capab := f.capabilities()
	if f.FilterByCapabilities {
		plugins = filterByCapabilities(plugins, capab)
	}
	var skipDirRegex *regexp.Regexp
	if f.SkipDirRegex != "" {
		skipDirRegex, err = regexp.Compile(f.SkipDirRegex)
		if err != nil {
			return nil, err
		}
	}
	var skipDirGlob glob.Glob
	if f.SkipDirGlob != "" {
		skipDirGlob, err = glob.Compile(f.SkipDirGlob)
		if err != nil {
			return nil, err
		}
	}

	scanRoots, err := f.scanRoots()
	if err != nil {
		return nil, err
	}

	var overrides []extractorOverride
	if len(f.ExtractorOverride) > 0 {
		pluginMap := make(map[string]filesystem.Extractor)
		for _, p := range plugins {
			if e, ok := p.(filesystem.Extractor); ok {
				pluginMap[e.Name()] = e
			}
		}

		for _, o := range f.ExtractorOverride {
			parts := strings.SplitN(o, ":", 2)
			pluginName := parts[0]
			globPattern := parts[1]
			extractor, ok := pluginMap[pluginName]
			if !ok {
				return nil, fmt.Errorf("plugin %q specified in --extractor-override not found or not a filesystem extractor", pluginName)
			}
			g, err := glob.Compile(globPattern)
			if err != nil {
				// This should not happen due to ValidateFlags.
				return nil, fmt.Errorf("invalid glob pattern %q in extractor override: %w", globPattern, err)
			}
			overrides = append(overrides, extractorOverride{
				glob:      g,
				extractor: extractor,
			})
		}
	}

	var extractorOverrideFn func(filesystem.FileAPI) []filesystem.Extractor
	if len(overrides) > 0 {
		extractorOverrideFn = func(api filesystem.FileAPI) []filesystem.Extractor {
			var result []filesystem.Extractor
			for _, o := range overrides {
				if o.glob.Match(api.Path()) {
					result = append(result, o.extractor)
				}
			}
			return result
		}
	}

	return &scalibr.ScanConfig{
		ScanRoots:         scanRoots,
		Plugins:           plugins,
		Capabilities:      capab,
		PathsToExtract:    f.PathsToExtract,
		IgnoreSubDirs:     f.IgnoreSubDirs,
		DirsToSkip:        f.dirsToSkip(scanRoots),
		SkipDirRegex:      skipDirRegex,
		SkipDirGlob:       skipDirGlob,
		MaxFileSize:       f.MaxFileSize,
		UseGitignore:      f.UseGitignore,
		StoreAbsolutePath: f.StoreAbsolutePath,
		ExtractorOverride: extractorOverrideFn,
	}, nil
}

// GetSPDXConfig creates an SPDXConfig struct based on the CLI flags.
func (f *Flags) GetSPDXConfig() convspdx.Config {
	var creators []common.Creator
	if len(f.SPDXCreators) > 0 {
		for _, item := range strings.Split(f.SPDXCreators, ",") {
			c := strings.Split(item, ":")
			cType := c[0]
			cName := c[1]
			creators = append(creators, common.Creator{
				CreatorType: cType,
				Creator:     cName,
			})
		}
	}
	return convspdx.Config{
		DocumentName:      f.SPDXDocumentName,
		DocumentNamespace: f.SPDXDocumentNamespace,
		Creators:          creators,
	}
}

// GetCDXConfig creates a CDXConfig struct based on the CLI flags.
func (f *Flags) GetCDXConfig() converter.CDXConfig {
	return converter.CDXConfig{
		ComponentName:    f.CDXComponentName,
		ComponentType:    f.CDXComponentType,
		ComponentVersion: f.CDXComponentVersion,
		Authors:          strings.Split(f.CDXAuthors, ","),
	}
}

// WriteScanResults writes SCALIBR scan results to files specified by the CLI flags.
func (f *Flags) WriteScanResults(result *scalibr.ScanResult) error {
	if len(f.ResultFile) > 0 {
		log.Infof("Writing scan results to %s", f.ResultFile)
		resultProto, err := proto.ScanResultToProto(result)
		if err != nil {
			return err
		}
		if err := proto.Write(f.ResultFile, resultProto); err != nil {
			return err
		}
	}
	if len(f.Output) > 0 {
		for _, item := range f.Output {
			o := strings.Split(item, "=")
			oFormat := o[0]
			oPath := o[1]
			log.Infof("Writing scan results to %s", oPath)
			if strings.Contains(oFormat, "proto") {
				resultProto, err := proto.ScanResultToProto(result)
				if err != nil {
					return err
				}
				if err := proto.WriteWithFormat(oPath, resultProto, oFormat); err != nil {
					return err
				}
			} else if strings.Contains(oFormat, "spdx23") {
				doc := converter.ToSPDX23(result, f.GetSPDXConfig())
				if err := binspdx.Write23(doc, oPath, oFormat); err != nil {
					return err
				}
			} else if strings.Contains(oFormat, "cdx") {
				doc := converter.ToCDX(result, f.GetCDXConfig())
				if err := cdx.Write(doc, oPath, oFormat); err != nil {
					return err
				}
			}
		}
	}
	return nil
}

// TODO(b/279413691): Allow commas in argument names.
func (f *Flags) pluginsToRun() ([]plugin.Plugin, error) {
	result := make([]plugin.Plugin, 0, len(f.PluginsToRun))
	pluginNames := multiStringToList(f.PluginsToRun)
	extractorNames := addPluginPrefixToGroups("extractors/", multiStringToList(f.ExtractorsToRun))
	detectorNames := addPluginPrefixToGroups("detectors/", multiStringToList(f.DetectorsToRun))
	annotatorNames := addPluginPrefixToGroups("annotators/", multiStringToList(f.AnnotatorsToRun))

	// Use the default plugins if nothing is specified.
	allPluginNames := slices.Concat(pluginNames, extractorNames, detectorNames, annotatorNames)
	if len(allPluginNames) == 0 {
		allPluginNames = []string{"default"}
	}

	for _, name := range allPluginNames {
		plugins, err := pl.FromNames([]string{name})
		if err != nil {
			return nil, err
		}

		// Apply plugin-specific config.
		for _, p := range plugins {
			if p.Name() == gobinary.Name {
				p.(*gobinary.Extractor).VersionFromContent = f.GoBinaryVersionFromContent
			}
			if p.Name() == binary.Name {
				p.(*binary.Detector).OfflineVulnDBPath = f.GovulncheckDBPath
			}
			if f.LocalRegistry != "" {
				switch p.Name() {
				case pomxmlnet.Name:
					p.(*pomxmlnet.Extractor).MavenClient.SetLocalRegistry(f.LocalRegistry)
				case requirements.Name:
					if client, ok := p.(*requirements.Enricher).Client.(*resolution.PyPIRegistryClient); ok {
						// The resolution client is the native PyPI registry client.
						client.SetLocalRegistry(f.LocalRegistry)
					}
				}
			}
		}

		result = append(result, plugins...)
	}

	return result, nil
}

// addPluginPrefixToGroups adds the specified prefix to the "default" and "all"
// plugin group names so that they're only applied for a specific plugin type
// so that e.g. --extractors=all only enables all extractors and not other plugins.
func addPluginPrefixToGroups(prefix string, pluginNames []string) []string {
	result := make([]string, 0, len(pluginNames))
	for _, p := range pluginNames {
		if p == "all" || p == "default" {
			p = prefix + p
		}
		result = append(result, p)
	}
	return result
}

func multiStringToList(arg []string) []string {
	var result []string
	for _, item := range arg {
		result = append(result, strings.Split(item, ",")...)
	}
	return result
}

func (f *Flags) scanRoots() ([]*scalibrfs.ScanRoot, error) {
	if f.RemoteImage != "" {
		imageOptions := f.scanRemoteImageOptions()
		fs, err := scalibrimage.NewFromRemoteName(f.RemoteImage, *imageOptions...)
		if err != nil {
			return nil, err
		}
		// We're scanning a virtual filesystem that describes the remote container.
		return []*scalibrfs.ScanRoot{{FS: fs, Path: ""}}, nil
	}

	if len(f.Root) != 0 {
		return scalibrfs.RealFSScanRoots(f.Root), nil
	}

	// If ImageTarball is set, do not set the root.
	// It is computed later on by ScanContainer(...) when the tarball is read.
	if f.ImageTarball != "" {
		return nil, nil
	}
	// If ImageLocal is set, do not set the root.
	// It is computed later on by ScanContainer(...) when the tarball is read.
	if f.ImageLocal != "" {
		return nil, nil
	}

	// Compute the default scan roots.
	var scanRoots []*scalibrfs.ScanRoot
	var scanRootPaths []string
	var err error
	if scanRootPaths, err = platform.DefaultScanRoots(f.WindowsAllDrives); err != nil {
		return nil, err
	}
	for _, r := range scanRootPaths {
		scanRoots = append(scanRoots, &scalibrfs.ScanRoot{FS: scalibrfs.DirFS(r), Path: r})
	}
	return scanRoots, nil
}

func (f *Flags) scanRemoteImageOptions() *[]remote.Option {
	imageOptions := []remote.Option{
		remote.WithAuthFromKeychain(authn.DefaultKeychain),
	}
	if f.ImagePlatform != "" {
		platformDetails := strings.Split(f.ImagePlatform, "/")
		imageOptions = append(imageOptions, remote.WithPlatform(
			v1.Platform{
				OS:           platformDetails[0],
				Architecture: platformDetails[1],
			},
		))
	}
	return &imageOptions
}

// All capabilities are enabled when running SCALIBR as a binary.
func (f *Flags) capabilities() *plugin.Capabilities {
	network := plugin.NetworkOnline
	if f.Offline {
		network = plugin.NetworkOffline
	}
	if f.RemoteImage != "" {
		// We're scanning a Linux container image whose filesystem is mounted to the host's disk.
		return &plugin.Capabilities{
			OS:            plugin.OSLinux,
			Network:       network,
			DirectFS:      true,
			RunningSystem: false,
		}
	}
	return &plugin.Capabilities{
		OS:            platform.OS(),
		Network:       network,
		DirectFS:      true,
		RunningSystem: true,
	}
}

// Filters the specified list of plugins (filesystem extractors, standalone extractors, detectors, enrichers)
// by removing all plugins that don't satisfy the specified capabilities.
func filterByCapabilities(plugins []plugin.Plugin, capab *plugin.Capabilities) []plugin.Plugin {
	fp := make([]plugin.Plugin, 0, len(plugins))
	for _, p := range plugins {
		if err := plugin.ValidateRequirements(p, capab); err == nil {
			fp = append(fp, p)
		}
	}
	return fp
}

func (f *Flags) dirsToSkip(scanRoots []*scalibrfs.ScanRoot) []string {
	paths, err := platform.DefaultIgnoredDirectories()
	if err != nil {
		log.Warnf("Failed to get default ignored directories: %v", err)
	}
	if len(f.DirsToSkip) > 0 {
		paths = append(paths, multiStringToList(f.DirsToSkip)...)
	}

	// Ignore paths that are not under Root.
	result := make([]string, 0, len(paths))
	for _, root := range scanRoots {
		path := root.Path
		if !strings.HasSuffix(path, string(os.PathSeparator)) {
			path += string(os.PathSeparator)
		}
		for _, p := range paths {
			if strings.HasPrefix(p, path) {
				result = append(result, p)
			}
		}
	}
	return result
}
