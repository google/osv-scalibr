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

package aspect

import (
	"encoding/json"
	"errors"
	"io"
	"net/url"
	"path/filepath"
	"sort"
	"strings"
)

// aspectOutputSuffix is the file name suffix of the metadata files written by the aspect.
const aspectOutputSuffix = ".scalibr.json"

// bepFile is a File message from a Build Event Protocol namedSetOfFiles event.
type bepFile struct {
	// Name is the path of the file relative to PathPrefix.
	Name string `json:"name"`
	// URI is where the file can be fetched from: file:// for local files, but bytestream:// when a
	// remote cache is configured, even for files that only exist locally.
	URI string `json:"uri"`
	// PathPrefix is the path of the output directory relative to the exec root.
	PathPrefix []string `json:"pathPrefix"`
}

// bepEvent contains the parts of a Build Event Protocol event used by the extractor.
type bepEvent struct {
	WorkspaceInfo *struct {
		LocalExecRoot string `json:"localExecRoot"`
	} `json:"workspaceInfo"`
	NamedSetOfFiles *struct {
		Files []bepFile `json:"files"`
	} `json:"namedSetOfFiles"`
}

// aspectOutputsFromBEP reads a Build Event Protocol JSON stream (as written by
// --build_event_json_file) and returns the local paths of all aspect metadata files it references.
//
// Events are decoded one at a time because single events can be megabytes long in large
// workspaces (e.g. the expanded target pattern). If the stream is truncated or malformed, the
// paths found so far are returned together with the decoding error.
func aspectOutputsFromBEP(r io.Reader) ([]string, error) {
	dec := json.NewDecoder(r)
	var execRoot string
	var files []bepFile
	var decodeErr error
	for {
		var ev bepEvent
		if err := dec.Decode(&ev); err != nil {
			if !errors.Is(err, io.EOF) {
				decodeErr = err
			}
			break
		}
		if ev.WorkspaceInfo != nil && ev.WorkspaceInfo.LocalExecRoot != "" {
			execRoot = ev.WorkspaceInfo.LocalExecRoot
		}
		if ev.NamedSetOfFiles == nil {
			continue
		}
		for _, f := range ev.NamedSetOfFiles.Files {
			if strings.HasSuffix(f.Name, aspectOutputSuffix) || strings.HasSuffix(f.URI, aspectOutputSuffix) {
				files = append(files, f)
			}
		}
	}

	// The exec root is only known once the workspace event has been read, so paths are resolved
	// after decoding the whole stream.
	seen := make(map[string]bool)
	var paths []string
	for _, f := range files {
		p := localPath(f, execRoot)
		if p == "" || seen[p] {
			continue
		}
		seen[p] = true
		paths = append(paths, p)
	}
	sort.Strings(paths)
	return paths, decodeErr
}

// localPath returns the local path of a file referenced in the BEP, or "" if it can't be
// determined.
func localPath(f bepFile, execRoot string) string {
	if u, err := url.Parse(f.URI); err == nil && u.Scheme == "file" {
		p := u.Path
		// On Windows, file:///C:/foo is parsed as the path /C:/foo.
		if len(p) >= 3 && p[0] == '/' && p[2] == ':' && isASCIILetter(p[1]) {
			p = p[1:]
		}
		return filepath.FromSlash(p)
	}
	// Other schemes (e.g. bytestream:// with a remote cache) don't point to the local file, but the
	// aspect's outputs are always written locally at <exec root>/<path prefix>/<name>.
	if execRoot == "" {
		return ""
	}
	parts := []string{execRoot}
	parts = append(parts, f.PathPrefix...)
	parts = append(parts, filepath.FromSlash(f.Name))
	return filepath.Join(parts...)
}

func isASCIILetter(c byte) bool {
	return ('a' <= c && c <= 'z') || ('A' <= c && c <= 'Z')
}
