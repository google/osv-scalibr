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

package veles

// Secret is a secret that can be found by a Detector and validated by a
// Validator.
//
// Detectors return slices of Secret and validators accept concrete types. That
// allows them to be used independently with maximum flexibility.
//
// While the interface is empty, each Secret should be convertible to and from
// the Veles protocol buffer message format; see the velesproto package.
// In order to not have the library explicitly depend on protocol buffers, we
// did not make that requirement part of the interface.
type Secret any
