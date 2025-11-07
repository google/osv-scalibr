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

// Package awsaccesskey contains Veles Secret types and Detectors for AWS access and secret key.
//
// ref: https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_access-keys.html
package awsaccesskey

// Credential is a Veles Secret that holds the value of the AWS Access Key and Secret Key credentials.
type Credential struct {
	AccessID string
	Secret   string
}
