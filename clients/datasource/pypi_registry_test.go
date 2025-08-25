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

package datasource_test

import (
	"net/url"
	"os"
	"path/filepath"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/osv-scalibr/clients/clienttest"
	"github.com/google/osv-scalibr/clients/datasource"
	"github.com/google/osv-scalibr/clients/internal/pypi"
)

const jsonResp = `{
		"files": [
		  {
			"core-metadata": false,
			"data-dist-info-metadata": false,
			"filename": "beautifulsoup4-4.0.1.tar.gz",
			"hashes": {
			  "sha256": "dc6bc8e8851a1c590c8cc8f25915180fdcce116e268d1f37fa991d2686ea38de"
			},
			"requires-python": null,
			"size": 51024,
			"upload-time": "2014-01-21T05:35:05.558877Z",
			"url": "https://files.pythonhosted.org/packages/6f/be/99dcf74d947cc1e7abef5d0c4572abcb479c33ef791d94453a8fd7987d8f/beautifulsoup4-4.0.1.tar.gz",
			"yanked": false
		  },
		  {
			"core-metadata": false,
			"data-dist-info-metadata": false,
			"filename": "beautifulsoup4-4.0.2.tar.gz",
			"hashes": {
			  "sha256": "353792f8246a9551b232949fb14dce21d9b6ced9207bf9f4a69a4c4eb46c8127"
			},
			"requires-python": null,
			"size": 51240,
			"upload-time": "2014-01-21T05:35:09.581933Z",
			"url": "https://files.pythonhosted.org/packages/a0/75/db36172ea767dd2f0c9817a99e24f7e9b79c2ce63eb2f8b867284cc60daf/beautifulsoup4-4.0.2.tar.gz",
			"yanked": false
		  },
		  {
			"core-metadata": {
			  "sha256": "524392d64a088e56a4232f50d6edb208dc03105394652acb72c6d5fa64c89f3e"
			},
			"data-dist-info-metadata": {
			  "sha256": "524392d64a088e56a4232f50d6edb208dc03105394652acb72c6d5fa64c89f3e"
			},
			"filename": "beautifulsoup4-4.12.3-py3-none-any.whl",
			"hashes": {
			  "sha256": "b80878c9f40111313e55da8ba20bdba06d8fa3969fc68304167741bbf9e082ed"
			},
			"requires-python": ">=3.6.0",
			"size": 147925,
			"upload-time": "2024-01-17T16:53:12.779164Z",
			"url": "https://files.pythonhosted.org/packages/b1/fe/e8c672695b37eecc5cbf43e1d0638d88d66ba3a44c4d321c796f4e59167f/beautifulsoup4-4.12.3-py3-none-any.whl",
			"yanked": false
		  },
		  {
			"core-metadata": false,
			"data-dist-info-metadata": false,
			"filename": "beautifulsoup4-4.12.3.tar.gz",
			"hashes": {
			  "sha256": "74e3d1928edc070d21748185c46e3fb33490f22f52a3addee9aee0f4f7781051"
			},
			"requires-python": ">=3.6.0",
			"size": 581181,
			"upload-time": "2024-01-17T16:53:17.902970Z",
			"url": "https://files.pythonhosted.org/packages/b3/ca/824b1195773ce6166d388573fc106ce56d4a805bd7427b624e063596ec58/beautifulsoup4-4.12.3.tar.gz",
			"yanked": false
		  },
		  {
			"core-metadata": {
			  "sha256": "d0aa787c2b55e5b0b3aff66f137cf33341c5e781cb87b4dc184cbb25c7ac0ab5"
			},
			"data-dist-info-metadata": {
			  "sha256": "d0aa787c2b55e5b0b3aff66f137cf33341c5e781cb87b4dc184cbb25c7ac0ab5"
			},
			"filename": "beautifulsoup4-4.13.0b2-py3-none-any.whl",
			"hashes": {
			  "sha256": "7e05ad0b6c26108d9990e2235e8a9b4e2c03ead6f391ceb60347f8ebea6b80ba"
			},
			"requires-python": ">=3.6.0",
			"size": 179607,
			"upload-time": "2024-03-20T13:00:33.355932Z",
			"url": "https://files.pythonhosted.org/packages/14/7e/e4313dad823c3a0751c99b9bc0182b1dd19aea164ce7445e9a70429b9e92/beautifulsoup4-4.13.0b2-py3-none-any.whl",
			"yanked": false
		  },
		  {
			"core-metadata": false,
			"data-dist-info-metadata": false,
			"filename": "beautifulsoup4-4.13.0b2.tar.gz",
			"hashes": {
			  "sha256": "c684ddec071aa120819889aa9e8940f85c3f3cdaa08e23b9fa26510387897bd5"
			},
			"requires-python": ">=3.6.0",
			"size": 550258,
			"upload-time": "2024-03-20T13:00:31.245327Z",
			"url": "https://files.pythonhosted.org/packages/81/bd/c97d94e2b96f03d1c50bc9de04130e014eda89322ba604923e0c251eb02e/beautifulsoup4-4.13.0b2.tar.gz",
			"yanked": false
		  },
		  {
			"filename": "beautifulsoup4-4.14.tar.gz",
			"yanked": "yanked"
		  }
		],
		"meta": {
		  "_last-serial": 22406780,
		  "api-version": "1.1"
		},
		"name": "beautifulsoup4",
		"versions": [
		  "4.0.1",
		  "4.0.2",
		  "4.12.3",
		  "4.13.0b2",
		  "4.14"
		]
}`

func TestGetVersions(t *testing.T) {
	srv := clienttest.NewMockHTTPServer(t)
	client := datasource.NewPyPIRegistryAPIClient(srv.URL, "")
	srv.SetResponse(t, "/beautifulsoup4/", []byte(jsonResp))

	got, err := client.GetIndex(t.Context(), "beautifulsoup4")
	if err != nil {
		t.Fatalf("failed to get versions of PyPI project %s: %v", "beautifulsoup4", err)
	}
	want := pypi.IndexResponse{
		Name: "beautifulsoup4",
		Files: []pypi.File{
			{
				Name: "beautifulsoup4-4.0.1.tar.gz",
				URL:  "https://files.pythonhosted.org/packages/6f/be/99dcf74d947cc1e7abef5d0c4572abcb479c33ef791d94453a8fd7987d8f/beautifulsoup4-4.0.1.tar.gz",
			},
			{
				Name: "beautifulsoup4-4.0.2.tar.gz",
				URL:  "https://files.pythonhosted.org/packages/a0/75/db36172ea767dd2f0c9817a99e24f7e9b79c2ce63eb2f8b867284cc60daf/beautifulsoup4-4.0.2.tar.gz",
			},
			{
				Name: "beautifulsoup4-4.12.3-py3-none-any.whl",
				URL:  "https://files.pythonhosted.org/packages/b1/fe/e8c672695b37eecc5cbf43e1d0638d88d66ba3a44c4d321c796f4e59167f/beautifulsoup4-4.12.3-py3-none-any.whl",
			},
			{
				Name: "beautifulsoup4-4.12.3.tar.gz",
				URL:  "https://files.pythonhosted.org/packages/b3/ca/824b1195773ce6166d388573fc106ce56d4a805bd7427b624e063596ec58/beautifulsoup4-4.12.3.tar.gz",
			},
			{
				Name: "beautifulsoup4-4.13.0b2-py3-none-any.whl",
				URL:  "https://files.pythonhosted.org/packages/14/7e/e4313dad823c3a0751c99b9bc0182b1dd19aea164ce7445e9a70429b9e92/beautifulsoup4-4.13.0b2-py3-none-any.whl",
			},
			{
				Name: "beautifulsoup4-4.13.0b2.tar.gz",
				URL:  "https://files.pythonhosted.org/packages/81/bd/c97d94e2b96f03d1c50bc9de04130e014eda89322ba604923e0c251eb02e/beautifulsoup4-4.13.0b2.tar.gz",
			},
			{
				Name:   "beautifulsoup4-4.14.tar.gz",
				Yanked: pypi.Yanked{Value: true},
			},
		},
		Versions: []string{
			"4.0.1",
			"4.0.2",
			"4.12.3",
			"4.13.0b2",
			"4.14",
		},
	}
	if diff := cmp.Diff(want, got); diff != "" {
		t.Errorf("GetIndex(%s) mismatch (-want +got):\n%s", "beautifulsoup4", diff)
	}
}

func TestPyPILocalRegistry(t *testing.T) {
	tempDir := t.TempDir()
	srv := clienttest.NewMockHTTPServer(t)
	client := datasource.NewPyPIRegistryAPIClient(srv.URL, tempDir)
	srv.SetResponse(t, "/beautifulsoup4/", []byte(jsonResp))

	_, err := client.GetIndex(t.Context(), "beautifulsoup4")
	if err != nil {
		t.Fatalf("failed to get versions of PyPI project %s: %v", "beautifulsoup4", err)
	}

	// Check that the JSON response is stored locally.
	parsed, err := url.Parse(srv.URL)
	if err != nil {
		t.Fatalf("failed to parse URL %s: %v", srv.URL, err)
	}
	filePath := filepath.Join(tempDir, parsed.Hostname(), "beautifulsoup4")
	content, err := os.ReadFile(filePath)
	if err != nil {
		t.Fatalf("failed to read file: %v", err)
	}
	if string(content) != jsonResp {
		t.Errorf("unexpected file content: got %s, want %s", string(content), jsonResp)
	}
}
