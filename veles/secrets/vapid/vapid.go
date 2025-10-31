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

// Package vapid contain the logic for finding "Firebase Cloud Messaging Web Push Certificate"
// also known as VAPID keys (Voluntary Application Server Identification)
//
// ref: https://firebase.google.com/docs/cloud-messaging/get-started?platform=web&_gl=1*vzrfcj*_up*MQ..*_ga*ODM5Mzk4NDUxLjE3NDU5MzczOTk.*_ga_CW55HF8NVT*MTc0NTkzNzM5OS4xLjAuMTc0NTkzNzM5OS4wLjAuMA..#configure_web_credentials_with
package vapid

type Keys struct {
	PrivateB64 string
	PublicB64  string
}
