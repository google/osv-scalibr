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
	"github.com/google/osv-scalibr/binary/spdx"
	"github.com/google/osv-scalibr/converter"
	"github.com/google/osv-scalibr/detector"
	"github.com/google/osv-scalibr/detector/govulncheck/binary"
	dl "github.com/google/osv-scalibr/detector/list"
	"github.com/google/osv-scalibr/extractor/filesystem"
	el "github.com/google/osv-scalibr/extractor/filesystem/list"
	"github.com/google/osv-scalibr/extractor/standalone"
	sl "github.com/google/osv-scalibr/extractor/standalone/list"
	scalibrfs "github.com/google/osv-scalibr/fs"
	"github.com/google/osv-scalibr/log"
	"github.com/google/osv-scalibr/plugin"
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
	Root                  string
	ResultFile            string
	Output                Array
	ExtractorsToRun       []string
	DetectorsToRun        []string
	PathsToExtract        []string
	IgnoreSubDirs         bool
	DirsToSkip            []string
	SkipDirRegex          string
	SkipDirGlob           string
	UseGitignore          bool
	RemoteImage           string
	ImagePlatform         string
	GovulncheckDBPath     string
	SPDXDocumentName      string
	SPDXDocumentNamespace string
	SPDXCreators          string
	CDXComponentName      string
	CDXComponentVersion   string
	CDXAuthors            string
	Verbose               bool
	ExplicitExtractors    bool
	FilterByCapabilities  bool
	StoreAbsolutePath     bool
	WindowsAllDrives      bool
	Offline               bool
}

var supportedOutputFormats = []string{
	"textproto", "binproto", "spdx23-tag-value", "spdx23-json", "spdx23-yaml", "cdx-json", "cdx-xml",
}

// ValidateFlags validates the passed command line flags.
func ValidateFlags(flags *Flags) error {
	if len(flags.ResultFile) == 0 && len(flags.Output) == 0 {
		return errors.New("either --result or --o needs to be set")
	}
	if flags.Root != "" && flags.WindowsAllDrives {
		return errors.New("--root and --windows-all-drives cannot be used together")
	}
	if flags.ImagePlatform != "" && len(flags.RemoteImage) == 0 {
		return errors.New("--image-platform cannot be used without --remote-image")
	}
	if err := validateResultPath(flags.ResultFile); err != nil {
		return fmt.Errorf("--result %w", err)
	}
	if err := validateOutput(flags.Output); err != nil {
		return fmt.Errorf("--o %w", err)
	}
	if err := validateImagePlatform(flags.ImagePlatform); err != nil {
		return fmt.Errorf("--image-platform %w", err)
	}
	// TODO(b/279413691): Use the Array struct to allow multiple occurrences of a list arg
	// e.g. --extractors=ex1 --extractors=ex2.
	if err := validateMultiStringArg(flags.ExtractorsToRun); err != nil {
		return fmt.Errorf("--extractors: %w", err)
	}
	if err := validateMultiStringArg(flags.DetectorsToRun); err != nil {
		return fmt.Errorf("--detectors: %w", err)
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
	if err := validateDetectorDependency(flags.DetectorsToRun, flags.ExtractorsToRun, flags.ExplicitExtractors); err != nil {
		return err
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

func validateDetectorDependency(detectors []string, extractors []string, requireExtractors bool) error {
	f := &Flags{
		ExtractorsToRun: extractors,
		DetectorsToRun:  detectors,
	}
	ex, stdex, err := f.extractorsToRun()
	if err != nil {
		return err
	}
	det, err := f.detectorsToRun()
	if err != nil {
		return err
	}
	exMap := make(map[string]bool)
	for _, e := range ex {
		exMap[e.Name()] = true
	}
	for _, e := range stdex {
		exMap[e.Name()] = true
	}
	if requireExtractors {
		for _, d := range det {
			for _, req := range d.RequiredExtractors() {
				if !exMap[req] {
					return fmt.Errorf("extractor %s must be turned on for Detector %s to run", req, d.Name())
				}
			}
		}
	}
	return nil
}

// GetScanConfig constructs a SCALIBR scan config from the provided CLI flags.
func (f *Flags) GetScanConfig() (*scalibr.ScanConfig, error) {
	extractors, standaloneExtractors, err := f.extractorsToRun()
	if err != nil {
		return nil, err
	}
	detectors, err := f.detectorsToRun()
	if err != nil {
		return nil, err
	}
	capab := f.capabilities()
	if f.FilterByCapabilities {
		extractors, standaloneExtractors, detectors = filterByCapabilities(extractors, standaloneExtractors, detectors, capab)
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

	return &scalibr.ScanConfig{
		ScanRoots:            scanRoots,
		FilesystemExtractors: extractors,
		StandaloneExtractors: standaloneExtractors,
		Detectors:            detectors,
		Capabilities:         capab,
		PathsToExtract:       f.PathsToExtract,
		IgnoreSubDirs:        f.IgnoreSubDirs,
		DirsToSkip:           f.dirsToSkip(scanRoots),
		SkipDirRegex:         skipDirRegex,
		SkipDirGlob:          skipDirGlob,
		UseGitignore:         f.UseGitignore,
		StoreAbsolutePath:    f.StoreAbsolutePath,
	}, nil
}

// GetSPDXConfig creates an SPDXConfig struct based on the CLI flags.
func (f *Flags) GetSPDXConfig() converter.SPDXConfig {
	creators := []common.Creator{}
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
	return converter.SPDXConfig{
		DocumentName:      f.SPDXDocumentName,
		DocumentNamespace: f.SPDXDocumentNamespace,
		Creators:          creators,
	}
}

// GetCDXConfig creates an CDXConfig struct based on the CLI flags.
func (f *Flags) GetCDXConfig() converter.CDXConfig {
	return converter.CDXConfig{
		ComponentName:    f.CDXComponentName,
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
				if err := spdx.Write23(doc, oPath, oFormat); err != nil {
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
func (f *Flags) extractorsToRun() ([]filesystem.Extractor, []standalone.Extractor, error) {
	if len(f.ExtractorsToRun) == 0 {
		return []filesystem.Extractor{}, []standalone.Extractor{}, nil
	}

	var fsExtractors []filesystem.Extractor
	var standaloneExtractors []standalone.Extractor

	// We need to check extractors individually as they may be defined in one or both lists.
	for _, name := range multiStringToList(f.ExtractorsToRun) {
		ex, err := el.ExtractorsFromNames([]string{name})
		stex, sterr := sl.ExtractorsFromNames([]string{name})

		if err != nil && sterr != nil { // both fails.
			return nil, nil, err
		}

		if err == nil {
			fsExtractors = append(fsExtractors, ex...)
		}

		if sterr == nil {
			standaloneExtractors = append(standaloneExtractors, stex...)
		}
	}

	return fsExtractors, standaloneExtractors, nil
}

func (f *Flags) detectorsToRun() ([]detector.Detector, error) {
	if len(f.DetectorsToRun) == 0 {
		return []detector.Detector{}, nil
	}
	dets, err := dl.DetectorsFromNames(multiStringToList(f.DetectorsToRun))
	if err != nil {
		return []detector.Detector{}, err
	}
	for _, d := range dets {
		if d.Name() == binary.Name {
			d.(*binary.Detector).OfflineVulnDBPath = f.GovulncheckDBPath
		}
	}
	return dets, nil
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

// Filters the specified list of plugins (filesystem extractors, standalone extractors, detectors)
// by removing all plugins that don't satisfy the specified capabilities.
func filterByCapabilities(
	f []filesystem.Extractor, s []standalone.Extractor,
	d []detector.Detector, capab *plugin.Capabilities) (
	[]filesystem.Extractor, []standalone.Extractor, []detector.Detector) {
	ff := make([]filesystem.Extractor, 0, len(f))
	sf := make([]standalone.Extractor, 0, len(s))
	df := make([]detector.Detector, 0, len(d))
	for _, ex := range f {
		if err := plugin.ValidateRequirements(ex, capab); err == nil {
			ff = append(ff, ex)
		}
	}
	for _, ex := range s {
		if err := plugin.ValidateRequirements(ex, capab); err == nil {
			sf = append(sf, ex)
		}
	}
	for _, det := range d {
		if err := plugin.ValidateRequirements(det, capab); err == nil {
			df = append(df, det)
		}
	}
	return ff, sf, df
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
