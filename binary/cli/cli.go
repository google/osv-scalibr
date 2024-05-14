// Copyright 2024 Google LLC
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

	"github.com/spdx/tools-golang/spdx/v2/common"
	"github.com/google/osv-scalibr/binary/proto"
	"github.com/google/osv-scalibr/binary/spdx"
	"github.com/google/osv-scalibr/converter"
	"github.com/google/osv-scalibr/detector"
	"github.com/google/osv-scalibr/detector/govulncheck/binary"
	dl "github.com/google/osv-scalibr/detector/list"
	extractor "github.com/google/osv-scalibr/extractor/filesystem"
	el "github.com/google/osv-scalibr/extractor/filesystem/list"
	"github.com/google/osv-scalibr/log"
	scalibr "github.com/google/osv-scalibr"
)

// Array is a type to be passed to flag.Var that supports arrays passed as repeated flags,
// e.g. ./scalibr -o binproto=out.bp -o spdx23-json=out.spdx.json
type Array []string

func (i *Array) String() string {
	return strings.Join(*i, ",")
}

// Set gets called whenever an a new instance of a flag is read during CLI arg parsing.
// For example, in the case of -o foo -o bar the library will call arr.Set("foo") then arr.Set("bar").
func (i *Array) Set(value string) error {
	*i = append(*i, strings.TrimSpace(value))
	return nil
}

// Get returns the underlying []string value stored by this flag struct.
func (i *Array) Get() any {
	return i
}

// Flags contains a field for all the cli flags that can be set.
type Flags struct {
	Root                  string
	ResultFile            string
	Output                Array
	ExtractorsToRun       string
	DetectorsToRun        string
	FilesToExtract        []string
	DirsToSkip            string
	SkipDirRegex          string
	GovulncheckDBPath     string
	SPDXDocumentName      string
	SPDXDocumentNamespace string
	SPDXCreators          string
	Verbose               bool
}

var supportedOutputFormats = []string{
	"textproto", "binproto", "spdx23-tag-value", "spdx23-json", "spdx23-yaml",
}

// ValidateFlags validates the passed command line flags.
func ValidateFlags(flags *Flags) error {
	if len(flags.ResultFile) == 0 && len(flags.Output) == 0 {
		return errors.New("either --result or --o needs to be set")
	}
	if err := validateResultPath(flags.ResultFile); err != nil {
		return fmt.Errorf("--result %w", err)
	}
	if err := validateOutput(flags.Output); err != nil {
		return fmt.Errorf("--o %w", err)
	}
	if len(flags.Root) == 0 {
		return errors.New("--root not set")
	}
	// TODO(b/279413691): Use the Array struct to allow multiple occurrences of a list arg
	// e.g. --extractors=ex1 --extractors=ex2.
	if err := validateListArg(flags.ExtractorsToRun); err != nil {
		return fmt.Errorf("--extractors: %w", err)
	}
	if err := validateListArg(flags.DetectorsToRun); err != nil {
		return fmt.Errorf("--detectors: %w", err)
	}
	if err := validateListArg(flags.DirsToSkip); err != nil {
		return fmt.Errorf("--skip-dirs: %w", err)
	}
	if err := validateRegex(flags.SkipDirRegex); err != nil {
		return fmt.Errorf("--skip-dir-regex: %w", err)
	}
	if err := validateDetectorDependency(flags.DetectorsToRun, flags.ExtractorsToRun); err != nil {
		return fmt.Errorf("--detectors: %w", err)
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
			return fmt.Errorf("invalid output format, should follow a format like -o textproto=result.textproto -o spdx23-json=result.spdx.json")
		}
		oFormat := o[0]
		if !slices.Contains(supportedOutputFormats, oFormat) {
			return fmt.Errorf("output format %q not recognized, supported formats are %v", oFormat, supportedOutputFormats)
		}
	}
	return nil
}

func validateSPDXCreators(creators string) error {
	if len(creators) == 0 {
		return nil
	}
	for _, item := range strings.Split(creators, ",") {
		c := strings.Split(item, ":")
		if len(c) != 2 {
			return fmt.Errorf("invalid spdx-creators format, should follow a format like --spdx-creators=Tool:SCALIBR,Organization:Google")
		}
	}
	return nil
}

func validateListArg(arg string) error {
	if len(arg) == 0 {
		return nil
	}
	for _, item := range strings.Split(arg, ",") {
		if len(item) == 0 {
			return fmt.Errorf("list item cannot be left empty")
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

func validateDetectorDependency(detectors string, extractors string) error {
	f := &Flags{
		ExtractorsToRun: extractors,
		DetectorsToRun:  detectors,
	}
	ex, err := f.extractorsToRun()
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
	for _, d := range det {
		for _, req := range d.RequiredExtractors() {
			if !exMap[req] {
				return fmt.Errorf("Extractor %s must be turned on for Detector %s to run", req, d.Name())
			}
		}
	}
	return nil
}

// GetScanConfig constructs a SCALIBR scan config from the provided CLI flags.
func (f *Flags) GetScanConfig() (*scalibr.ScanConfig, error) {
	extractors, err := f.extractorsToRun()
	if err != nil {
		return nil, err
	}
	detectors, err := f.detectorsToRun()
	if err != nil {
		return nil, err
	}
	var skipDirRegex *regexp.Regexp
	if f.SkipDirRegex != "" {
		skipDirRegex, err = regexp.Compile(f.SkipDirRegex)
		if err != nil {
			return nil, err
		}
	}
	return &scalibr.ScanConfig{
		ScanRoot:            f.Root,
		InventoryExtractors: extractors,
		Detectors:           detectors,
		FilesToExtract:      f.FilesToExtract,
		DirsToSkip:          f.dirsToSkip(),
		SkipDirRegex:        skipDirRegex,
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
			}
		}
	}
	return nil
}

// TODO(b/279413691): Allow commas in argument names.
func (f *Flags) extractorsToRun() ([]extractor.InventoryExtractor, error) {
	if len(f.ExtractorsToRun) == 0 {
		return []extractor.InventoryExtractor{}, nil
	}
	return el.ExtractorsFromNames(strings.Split(f.ExtractorsToRun, ","))
}

func (f *Flags) detectorsToRun() ([]detector.Detector, error) {
	if len(f.DetectorsToRun) == 0 {
		return []detector.Detector{}, nil
	}
	dets, err := dl.DetectorsFromNames(strings.Split(f.DetectorsToRun, ","))
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

func (f *Flags) dirsToSkip() []string {
	paths := []string{"/dev", "/proc", "/sys"}
	if len(f.DirsToSkip) > 0 {
		paths = append(paths, strings.Split(f.DirsToSkip, ",")...)
	}
	// Convert absolute paths into paths relative to f.Root.
	result := make([]string, 0, len(paths))
	prefix := f.Root
	if !strings.HasSuffix(prefix, string(os.PathSeparator)) {
		prefix += string(os.PathSeparator)
	}
	for _, p := range paths {
		if strings.HasPrefix(p, prefix) { // Ignore paths that are not under Root.
			result = append(result, strings.TrimPrefix(p, prefix))
		}
	}
	return result
}

func keys(m map[string][]string) []string {
	ret := make([]string, 0, len(m))
	for k := range m {
		ret = append(ret, k)
	}
	return ret
}
