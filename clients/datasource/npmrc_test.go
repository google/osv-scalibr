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
	"encoding/base64"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"testing"

	"github.com/google/osv-scalibr/clients/datasource"
)

// These tests rely on using 'globalconfig' and 'userconfig' in the package .npmrc to override their default locations.
// It's also possible for environment variables or the builtin npmrc to mess with these tests.

func createTempNpmrc(t *testing.T, filename string) string {
	t.Helper()
	dir := t.TempDir()
	file := filepath.Join(dir, filename)
	f, err := os.Create(file)
	if err != nil {
		t.Fatalf("could not create test npmrc file: %v", err)
	}
	f.Close()

	return file
}

func writeToNpmrc(t *testing.T, file string, lines ...string) {
	t.Helper()
	f, err := os.OpenFile(file, os.O_APPEND|os.O_WRONLY, 0666)
	if err != nil {
		t.Fatalf("could not write to test npmrc file: %v", err)
	}
	defer f.Close()
	for _, line := range lines {
		if _, err := fmt.Fprintln(f, line); err != nil {
			t.Fatalf("could not write to test npmrc file: %v", err)
		}
	}
}

type testNpmrcFiles struct {
	global  string
	user    string
	project string
}

func makeBlankNpmrcFiles(t *testing.T) testNpmrcFiles {
	t.Helper()
	var files testNpmrcFiles
	files.global = createTempNpmrc(t, "npmrc")
	files.user = createTempNpmrc(t, ".npmrc")
	files.project = createTempNpmrc(t, ".npmrc")
	writeToNpmrc(t, files.project, "globalconfig="+files.global, "userconfig="+files.user)

	return files
}

func checkNPMRegistryRequest(t *testing.T, config datasource.NPMRegistryConfig, urlComponents []string, wantURL string, wantAuth string) {
	t.Helper()
	mt := &mockTransport{}
	httpClient := &http.Client{Transport: mt}
	resp, err := config.MakeRequest(t.Context(), httpClient, urlComponents...)
	if err != nil {
		t.Fatalf("error making request: %v", err)
	}
	defer resp.Body.Close()
	if len(mt.Requests) != 1 {
		t.Fatalf("unexpected number of requests made: %v", len(mt.Requests))
	}
	req := mt.Requests[0]
	gotURL := req.URL.String()
	if gotURL != wantURL {
		t.Errorf("MakeRequest() URL was %s, want %s", gotURL, wantURL)
	}
	gotAuth := req.Header.Get("Authorization")
	if gotAuth != wantAuth {
		t.Errorf("MakeRequest() Authorization was \"%s\", want \"%s\"", gotAuth, wantAuth)
	}
}

func TestLoadNPMRegistryConfig_WithNoRegistries(t *testing.T) {
	npmrcFiles := makeBlankNpmrcFiles(t)

	config, err := datasource.LoadNPMRegistryConfig(filepath.Dir(npmrcFiles.project))
	if err != nil {
		t.Fatalf("could not parse npmrc: %v", err)
	}

	if nRegs := len(config.ScopeURLs); nRegs != 1 {
		t.Errorf("expected 1 npm registry, got %v", nRegs)
	}

	checkNPMRegistryRequest(t, config, []string{"@test/package", "1.2.3"},
		"https://registry.npmjs.org/@test%2fpackage/1.2.3", "")
}

func TestLoadNPMRegistryConfig_WithAuth(t *testing.T) {
	npmrcFiles := makeBlankNpmrcFiles(t)
	writeToNpmrc(t, npmrcFiles.project,
		"registry=https://registry1.test.com",
		"//registry1.test.com/:_auth=bXVjaDphdXRoCg==",
		"@test1:registry=https://registry2.test.com",
		"//registry2.test.com/:_authToken=c3VjaCB0b2tlbgo=",
		"@test2:registry=https://sub.registry2.test.com",
		"//sub.registry2.test.com:username=user",
		"//sub.registry2.test.com:_password=d293Cg==",
	)

	config, err := datasource.LoadNPMRegistryConfig(filepath.Dir(npmrcFiles.project))
	if err != nil {
		t.Fatalf("could not parse npmrc: %v", err)
	}

	checkNPMRegistryRequest(t, config, []string{"foo"}, "https://registry1.test.com/foo", "Basic bXVjaDphdXRoCg==")
	checkNPMRegistryRequest(t, config, []string{"@test0/bar"}, "https://registry1.test.com/@test0%2fbar", "Basic bXVjaDphdXRoCg==")
	checkNPMRegistryRequest(t, config, []string{"@test1/baz"}, "https://registry2.test.com/@test1%2fbaz", "Bearer c3VjaCB0b2tlbgo=")
	checkNPMRegistryRequest(t, config, []string{"@test2/test"}, "https://sub.registry2.test.com/@test2%2ftest", "Basic dXNlcjp3b3cK")
}

// Do not make this test parallel because it calls t.Setenv()
func TestLoadNPMRegistryConfig_WithOverrides(t *testing.T) {
	check := func(t *testing.T, npmrcFiles testNpmrcFiles, wantURLs [5]string) {
		t.Helper()
		config, err := datasource.LoadNPMRegistryConfig(filepath.Dir(npmrcFiles.project))
		if err != nil {
			t.Fatalf("could not parse npmrc: %v", err)
		}
		checkNPMRegistryRequest(t, config, []string{"pkg"}, wantURLs[0], "")
		checkNPMRegistryRequest(t, config, []string{"@general/pkg"}, wantURLs[1], "")
		checkNPMRegistryRequest(t, config, []string{"@global/pkg"}, wantURLs[2], "")
		checkNPMRegistryRequest(t, config, []string{"@user/pkg"}, wantURLs[3], "")
		checkNPMRegistryRequest(t, config, []string{"@project/pkg"}, wantURLs[4], "")
	}

	npmrcFiles := makeBlankNpmrcFiles(t)
	writeToNpmrc(t, npmrcFiles.project, "@project:registry=https://project.registry.com")
	writeToNpmrc(t, npmrcFiles.user, "@user:registry=https://user.registry.com")
	writeToNpmrc(t, npmrcFiles.global,
		"@global:registry=https://global.registry.com",
		"@general:registry=https://general.global.registry.com",
		"registry=https://global.registry.com",
	)
	wantURLs := [5]string{
		"https://global.registry.com/pkg",
		"https://general.global.registry.com/@general%2fpkg",
		"https://global.registry.com/@global%2fpkg",
		"https://user.registry.com/@user%2fpkg",
		"https://project.registry.com/@project%2fpkg",
	}
	check(t, npmrcFiles, wantURLs)

	// override global in user
	writeToNpmrc(t, npmrcFiles.user,
		"@general:registry=https://general.user.registry.com",
		"registry=https://user.registry.com",
	)
	wantURLs[0] = "https://user.registry.com/pkg"
	wantURLs[1] = "https://general.user.registry.com/@general%2fpkg"
	check(t, npmrcFiles, wantURLs)

	// override global/user in project
	writeToNpmrc(t, npmrcFiles.project,
		"@general:registry=https://general.project.registry.com",
		"registry=https://project.registry.com",
	)
	wantURLs[0] = "https://project.registry.com/pkg"
	wantURLs[1] = "https://general.project.registry.com/@general%2fpkg"
	check(t, npmrcFiles, wantURLs)

	// override global/user/project in environment variable
	t.Setenv("NPM_CONFIG_REGISTRY", "https://environ.registry.com")
	wantURLs[0] = "https://environ.registry.com/pkg"
	check(t, npmrcFiles, wantURLs)
}

func TestNPMRegistryAuths(t *testing.T) {
	b64enc := func(s string) string {
		t.Helper()
		return base64.StdEncoding.EncodeToString([]byte(s))
	}
	tests := []struct {
		name       string
		config     datasource.NpmrcConfig
		requestURL string
		wantAuth   string
	}{
		// Auth tests adapted from npm-registry-fetch
		// https://github.com/npm/npm-registry-fetch/blob/237d33b45396caa00add61e0549cf09fbf9deb4f/test/auth.js
		{
			name: "basic auth",
			config: datasource.NpmrcConfig{
				"//my.custom.registry/here/:username":  "user",
				"//my.custom.registry/here/:_password": b64enc("pass"),
			},
			requestURL: "https://my.custom.registry/here/",
			wantAuth:   "Basic " + b64enc("user:pass"),
		},
		{
			name: "token auth",
			config: datasource.NpmrcConfig{
				"//my.custom.registry/here/:_authToken": "c0ffee",
				"//my.custom.registry/here/:token":      "nope",
				"//my.custom.registry/:_authToken":      "7ea",
				"//my.custom.registry/:token":           "nope",
			},
			requestURL: "https://my.custom.registry/here//foo/-/foo.tgz",
			wantAuth:   "Bearer c0ffee",
		},
		{
			name: "_auth auth",
			config: datasource.NpmrcConfig{
				"//my.custom.registry/:_auth":      "decafbad",
				"//my.custom.registry/here/:_auth": "c0ffee",
			},
			requestURL: "https://my.custom.registry/here//asdf/foo/bard/baz",
			wantAuth:   "Basic c0ffee",
		},
		{
			name: "_auth username:pass auth",
			config: datasource.NpmrcConfig{
				"//my.custom.registry/here/:_auth": b64enc("foo:bar"),
			},
			requestURL: "https://my.custom.registry/here/",
			wantAuth:   "Basic " + b64enc("foo:bar"),
		},
		{
			name: "ignore user/pass when _auth is set",
			config: datasource.NpmrcConfig{
				"//registry/:_auth":     b64enc("not:foobar"),
				"//registry/:username":  "foo",
				"//registry/:_password": b64enc("bar"),
			},
			requestURL: "http://registry/pkg/-/pkg-1.2.3.tgz",
			wantAuth:   "Basic " + b64enc("not:foobar"),
		},
		{
			name: "different hosts for uri vs registry",
			config: datasource.NpmrcConfig{
				"//my.custom.registry/here/:_authToken": "c0ffee",
				"//my.custom.registry/here/:token":      "nope",
			},
			requestURL: "https://some.other.host/",
			wantAuth:   "",
		},
		{
			name: "do not be thrown by other weird configs",
			config: datasource.NpmrcConfig{
				"@asdf:_authToken":                 "does this work?",
				"//registry.npmjs.org:_authToken":  "do not share this",
				"_authToken":                       "definitely do not share this, either",
				"//localhost:15443:_authToken":     "wrong",
				"//localhost:15443/foo:_authToken": "correct bearer token",
				"//localhost:_authToken":           "not this one",
				"//other-registry:_authToken":      "this should not be used",
				"@asdf:registry":                   "https://other-registry/",
			},
			requestURL: "http://localhost:15443/foo/@asdf/bar/-/bar-1.2.3.tgz",
			wantAuth:   "Bearer correct bearer token",
		},
		// Some extra tests, based on experimentation with npm config
		{
			name: "exact package path uri",
			config: datasource.NpmrcConfig{
				"//custom.registry/:_authToken":         "less specific match",
				"//custom.registry/package:_authToken":  "exact match",
				"//custom.registry/package/:_authToken": "no match trailing slash",
			},
			requestURL: "http://custom.registry/package",
			wantAuth:   "Bearer exact match",
		},
		{
			name: "percent-encoding case-sensitivity",
			config: datasource.NpmrcConfig{
				"//custom.registry/:_authToken":                 "expected",
				"//custom.registry/@scope%2Fpackage:_authToken": "bad config",
			},
			requestURL: "http://custom.registry/@scope%2fpackage",
			wantAuth:   "Bearer expected",
		},
		{
			name: "require both user and pass",
			config: datasource.NpmrcConfig{
				"//custom.registry/:_authToken":  "fallback",
				"//custom.registry/foo:username": "user",
			},
			requestURL: "https://custom.registry/foo/bar",
			wantAuth:   "Bearer fallback",
		},
		{
			name: "don't inherit username",
			config: datasource.NpmrcConfig{
				"//custom.registry/:_authToken":       "fallback",
				"//custom.registry/foo:username":      "user",
				"//custom.registry/foo/bar:_password": b64enc("pass"),
			},
			requestURL: "https://custom.registry/foo/bar/baz",
			wantAuth:   "Bearer fallback",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			config := datasource.ParseNPMRegistryInfo(tt.config)
			// Send off requests to mockTransport to see the auth headers being added.
			mt := &mockTransport{}
			httpClient := &http.Client{Transport: mt}
			resp, err := config.Auths.GetAuth(tt.requestURL).Get(t.Context(), httpClient, tt.requestURL)
			if err != nil {
				t.Fatalf("error making request: %v", err)
			}
			defer resp.Body.Close()
			if len(mt.Requests) != 1 {
				t.Fatalf("unexpected number of requests made: %v", len(mt.Requests))
			}
			header := mt.Requests[0].Header
			if got := header.Get("Authorization"); got != tt.wantAuth {
				t.Errorf("authorization header got = \"%s\", want \"%s\"", got, tt.wantAuth)
			}
		})
	}
}
