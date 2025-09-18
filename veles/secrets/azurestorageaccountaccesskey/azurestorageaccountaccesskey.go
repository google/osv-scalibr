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

// Package azurestorageaccountaccesskey contains a Veles Secret type and a Detector for [Azure storage account access key](https://learn.microsoft.com/en-us/purview/sit-defn-azure-storage-account-key-generic)
package azurestorageaccountaccesskey

// AzureStorageAccountAccessKey is a Veles Secret that holds relevant information for a [Azure storage account access key](https://learn.microsoft.com/en-us/purview/sit-defn-azure-storage-account-key-generic)
type AzureStorageAccountAccessKey struct {
	Key string
}
