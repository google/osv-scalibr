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
	"context"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/osv-scalibr/clients/clienttest"
	"github.com/google/osv-scalibr/clients/datasource"
	"github.com/google/osv-scalibr/clients/datasource/internal/pypi"
)

func TestGetVersions(t *testing.T) {
	srv := clienttest.NewMockHTTPServer(t)
	client := datasource.NewPyPIRegistryAPIClient(srv.URL)
	srv.SetResponse(t, "/simple/beautifulsoup4/", []byte(`
	{
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
		  "4.13.0b2"
		]
  }
	`))

	got, err := client.GetVersions(context.Background(), "beautifulsoup4")
	if err != nil {
		t.Fatalf("failed to get versions of PyPI project %s: %v", "beautifulsoup4", err)
	}
	want := []string{
		"4.0.1",
		"4.0.2",
		"4.12.3",
		"4.13.0b2",
	}
	if diff := cmp.Diff(want, got); diff != "" {
		t.Errorf("GetVersions(%s) mismatch (-want +got):\n%s", "beautifulsoup4", diff)
	}
}

func TestGetVersionJson(t *testing.T) {
	srv := clienttest.NewMockHTTPServer(t)
	client := datasource.NewPyPIRegistryAPIClient(srv.URL)
	srv.SetResponse(t, "pypi/sampleproject/3.0.0/json", []byte(`
	{
		"info": {
			"author": "",
			"author_email": "\"A. Random Developer\" <author@example.com>",
			"bugtrack_url": null,
			"classifiers": [
				"Development Status :: 3 - Alpha",
				"Intended Audience :: Developers",
				"License :: OSI Approved :: MIT License",
				"Programming Language :: Python :: 3",
				"Programming Language :: Python :: 3 :: Only",
				"Programming Language :: Python :: 3.10",
				"Programming Language :: Python :: 3.11",
				"Programming Language :: Python :: 3.7",
				"Programming Language :: Python :: 3.8",
				"Programming Language :: Python :: 3.9",
				"Topic :: Software Development :: Build Tools"
			],
			"description": "...",
			"description_content_type": "text/markdown",
			"docs_url": null,
			"download_url": "",
			"downloads": {
				"last_day": -1,
				"last_month": -1,
				"last_week": -1
			},
			"home_page": "",
			"keywords": "sample,setuptools,development",
			"license": "... ",
			"maintainer": "",
			"maintainer_email": "\"A. Great Maintainer\" <maintainer@example.com>",
			"name": "sampleproject",
			"package_url": "https://pypi.org/project/sampleproject/",
			"platform": null,
			"project_url": "https://pypi.org/project/sampleproject/",
			"project_urls": {
				"Bug Reports": "https://github.com/pypa/sampleproject/issues",
				"Funding": "https://donate.pypi.org",
				"Homepage": "https://github.com/pypa/sampleproject",
				"Say Thanks!": "http://saythanks.io/to/example",
				"Source": "https://github.com/pypa/sampleproject/"
			},
			"release_url": "https://pypi.org/project/sampleproject/3.0.0/",
			"requires_dist": [
				"peppercorn",
				"check-manifest ; extra == 'dev'",
				"coverage ; extra == 'test'"
			],
			"requires_python": ">=3.7",
			"summary": "A sample Python project",
			"version": "3.0.0",
			"yanked": false,
			"yanked_reason": null
		},
		"last_serial": 15959178,
		"urls": [
			{
				"comment_text": "",
				"digests": {
					"blake2b_256": "eca85ec62d18adde798d33a170e7f72930357aa69a60839194c93eb0fb05e59c",
					"md5": "e46bfece301c915db29ade44a4932039",
					"sha256": "2e52702990c22cf1ce50206606b769fe0dbd5646a32873916144bd5aec5473b3"
				},
				"downloads": -1,
				"filename": "sampleproject-3.0.0-py3-none-any.whl",
				"has_sig": false,
				"md5_digest": "e46bfece301c915db29ade44a4932039",
				"packagetype": "bdist_wheel",
				"python_version": "py3",
				"requires_python": ">=3.7",
				"size": 4662,
				"upload_time": "2022-12-01T18:51:00",
				"upload_time_iso_8601": "2022-12-01T18:51:00.007372Z",
				"url": "https://files.pythonhosted.org/packages/ec/a8/5ec62d18adde798d33a170e7f72930357aa69a60839194c93eb0fb05e59c/sampleproject-3.0.0-py3-none-any.whl",
				"yanked": false,
				"yanked_reason": null
			},
			{
				"comment_text": "",
				"digests": {
					"blake2b_256": "672a9f056e5fa36e43ef1037ff85581a2963cde420457de0ef29c779d41058ca",
					"md5": "46a92a8a919062028405fdf232b508b0",
					"sha256": "117ed88e5db073bb92969a7545745fd977ee85b7019706dd256a64058f70963d"
				},
				"downloads": -1,
				"filename": "sampleproject-3.0.0.tar.gz",
				"has_sig": false,
				"md5_digest": "46a92a8a919062028405fdf232b508b0",
				"packagetype": "sdist",
				"python_version": "source",
				"requires_python": ">=3.7",
				"size": 5330,
				"upload_time": "2022-12-01T18:51:01",
				"upload_time_iso_8601": "2022-12-01T18:51:01.420127Z",
				"url": "https://files.pythonhosted.org/packages/67/2a/9f056e5fa36e43ef1037ff85581a2963cde420457de0ef29c779d41058ca/sampleproject-3.0.0.tar.gz",
				"yanked": false,
				"yanked_reason": null
			}
		],
		"vulnerabilities": []
	}
	`))

	got, err := client.GetVersionJSON(context.Background(), "sampleproject", "3.0.0")
	if err != nil {
		t.Fatalf("failed to get version JSON of PyPI project %s %s: %v", "sampleproject", "3.0.0", err)
	}
	want := pypi.JSONResponse{
		Info: pypi.Info{
			RequiresDist: []string{
				"peppercorn",
				"check-manifest ; extra == 'dev'",
				"coverage ; extra == 'test'",
			},
			Yanked: false,
		},
		URLs: []pypi.URL{
			{
				Digests: pypi.Digests{
					SHA256: "2e52702990c22cf1ce50206606b769fe0dbd5646a32873916144bd5aec5473b3",
				},
			},
			{
				Digests: pypi.Digests{
					SHA256: "117ed88e5db073bb92969a7545745fd977ee85b7019706dd256a64058f70963d",
				},
			},
		},
	}
	if diff := cmp.Diff(want, got); diff != "" {
		t.Errorf("GetVersionJSON(%s, %s) mismatch (-want +got):\n%s", "sampleproject", "3.0.0", diff)
	}
}
