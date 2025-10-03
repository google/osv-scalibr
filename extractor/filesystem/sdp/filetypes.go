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

package sdp

import (
	"path/filepath"
	"strings"

	"github.com/google/osv-scalibr/inventory"
)

type extensionsToType struct {
	extensions []string
	fileType   inventory.FileType
}

var extensionsToTypes = []extensionsToType{
	{
		extensions: []string{"avro"},
		fileType:   inventory.AvroFileType,
	},
	{
		extensions: []string{"csv"},
		fileType:   inventory.CSVFileType,
	},
	{
		extensions: []string{
			"xlsm",
			"xlsx",
			"xltm",
			"xltx",
		},
		fileType: inventory.ExcelFileType,
	},
	{
		extensions: []string{
			"htm",
			"html",
		},
		fileType: inventory.HTMLFileType,
	},
	{
		extensions: []string{
			"bmp",
			"gif",
			"jpe",
			"jpeg",
			"jpg",
			"jpg:large",
			"jpg:orig",
			"jpg:raw",
			"jpg:small",
			"jpg:thumb",
			"png",
			"png:orig",
		},
		fileType: inventory.ImageFileType,
	},
	{
		extensions: []string{
			"json",
			"jsonl",
		},
		fileType: inventory.JSONFileType,
	},
	{
		extensions: []string{"pdf"},
		fileType:   inventory.PDFFileType,
	},
	{
		extensions: []string{
			"pot",
			"potm",
			"potx",
			"pptm",
			"pptx",
		},
		fileType: inventory.PowerPointFileType,
	},
	{
		extensions: []string{
			"bat",
			"c",
			"c++",
			"cc",
			"cmd",
			"cpp",
			"cs",
			"css",
			"cxx",
			"dart",
			"dot",
			"go",
			"h",
			"h++",
			"hh",
			"hpp",
			"hs",
			"htm",
			"html",
			"hxx",
			"java",
			"js",
			"kix",
			"kml",
			"kt",
			"lhs",
			"lua",
			"m",
			"ml",
			"ocaml",
			"perl",
			"php",
			"pht",
			"phtml",
			"pl",
			"ps1",
			"py",
			"pyw",
			"rb",
			"rbw",
			"rc",
			"rs",
			"rss",
			"scala",
			"scpt",
			"scr",
			"script",
			"sh",
			"shtm",
			"shtml",
			"sql",
			"swift",
			"vb",
			"vbs",
			"wml",
			"xcodeproj",
			"xhtml",
			"xml",
			"xsd",
			"xsl",
			"yaml",
			"yml",
		},
		fileType: inventory.SourceCodeFileType,
	},
	{
		extensions: []string{
			"asc",
			"brf",
			"cfm",
			"cgi",
			"conf",
			"config",
			"dat",
			"eml",
			"epub",
			"ged",
			"ics",
			"ini",
			"lnk",
			"log",
			"m3u",
			"md",
			"markdown",
			"mkd",
			"mli",
			"plist",
			"properties",
			"prototxt",
			"tex",
			"text",
			"textproto",
			"txt",
			"vcard",
			"vcs",
		},
		fileType: inventory.TextFileType,
	},
	{
		extensions: []string{"tsv"},
		fileType:   inventory.TSVFileType,
	},
	{
		extensions: []string{
			"docm",
			"docx",
			"dotm",
			"dotx",
		},
		fileType: inventory.WordFileType,
	},
}

// extToTypeMap is a map from file extensions to their corresponding inventory.FileType.
var extToTypeMap = buildExtToTypeMap()

func buildExtToTypeMap() map[string]inventory.FileType {
	m := make(map[string]inventory.FileType)
	for _, mapping := range extensionsToTypes {
		for _, ext := range mapping.extensions {
			m[ext] = mapping.fileType
		}
	}
	return m
}

func getExtension(path string) string {
	base := filepath.Base(path)

	// Handle special cases: ".", ".."
	if base == "." || base == ".." {
		return ""
	}

	dot := strings.LastIndex(base, ".")
	if dot == -1 || dot == len(base)-1 {
		return ""
	}

	if dot == 0 {
		// If the last dot is the first character of the file name, then it's a hidden file with no extension (like .bashrc).
		return ""
	}
	return base[dot+1:]
}

func getFileTypeForPath(path string) inventory.FileType {
	ext := getExtension(strings.ToLower(path))
	fileType, exists := extToTypeMap[ext]
	if !exists {
		return inventory.UnknownFileType
	}
	return fileType
}
