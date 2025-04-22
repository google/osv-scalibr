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

package groupid

var artifactIDToGroupID = map[string]string{
	"spring-web":                    "org.springframework",
	"spring-webflux":                "org.springframework",
	"spring-webmvc":                 "org.springframework",
	"spring-webmvc-portlet":         "org.springframework",
	"spring-webmvc-struts":          "org.springframework",
	"spring-websocket":              "org.springframework",
	"org/apache/axis":               "org.apache.axis",
	"axis":                          "org.apache.axis",
	"org.apache.tomcat-catalina":    "org.apache.tomcat",
	"org.apache.tomcat-catalina-ha": "org.apache.tomcat",
}
