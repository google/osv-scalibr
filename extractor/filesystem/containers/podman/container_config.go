// Copyright 2025 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//	http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
package podman

import (
	"net"
)

// ContainerConfig is a subset of the Podman's actual ContainerConfig
type ContainerConfig struct {
	ID            string   `json:"id"`
	Name          string   `json:"name"`
	Pod           string   `json:"pod,omitempty"`
	Namespace     string   `json:"namespace,omitempty"`
	LockID        uint32   `json:"lockID"`
	CreateCommand []string `json:"CreateCommand,omitempty"`
	RawImageName  string   `json:"RawImageName,omitempty"`
	Dependencies  []string

	// embedded sub-configs
	ContainerRootFSConfig
	ContainerNetworkConfig
}

type ContainerRootFSConfig struct {
	RootfsImageID    string   `json:"rootfsImageID,omitempty"`
	RootfsImageName  string   `json:"rootfsImageName,omitempty"`
	Rootfs           string   `json:"rootfs,omitempty"`
	RootfsOverlay    bool     `json:"rootfs_overlay,omitempty"`
	RootfsMapping    *string  `json:"rootfs_mapping,omitempty"`
	Mounts           []string `json:"mounts,omitempty"`
	CreateWorkingDir bool     `json:"createWorkingDir,omitempty"`
}

type ContainerNetworkConfig struct {
	CreateNetNS        bool                `json:"createNetNS"`
	StaticIP           net.IP              `json:"staticIP,omitempty"`
	ExposedPorts       map[uint16][]string `json:"exposedPorts,omitempty"`
	UseImageResolvConf bool
	UseImageHostname   bool `json:"useImageHostname"`
	UseImageHosts      bool
	BaseHostsFile      string              `json:"baseHostsFile,omitempty"`
	NetworkOptions     map[string][]string `json:"network_options,omitempty"`
}
