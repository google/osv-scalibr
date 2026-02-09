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

// Package vapid contain the logic for finding VAPID keys (Voluntary Application Server Identification)
//
// ref: https://web.dev/articles/push-notifications-web-push-protocol
package vapid

// Key holds the content of a VAPID key
type Key struct {
	PrivateB64 string
	PublicB64  string
}
