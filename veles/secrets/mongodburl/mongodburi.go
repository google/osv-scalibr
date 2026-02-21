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

package mongodbconnectionurl

// MongoDBConnectionURL is a Veles Secret that holds a MongoDB connection URL
// containing credentials (user:password).
//
// Per the MongoDB connection string spec, the following characters in the
// username or password must be percent-encoded: $ : / ? # [ ] @
//
// Examples:
//
//	mongodb://myUser:myPass@localhost
//	mongodb://myUser:D1fficultP%40ssw0rd@mongodb0.example.com:27017/?authSource=admin
//	mongodb+srv://myUser:myPass@cluster0.example.net/myDB?retryWrites=true
type MongoDBConnectionURL struct {
	URL string
}
