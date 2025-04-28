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
	"time"
)

// Container struct contains the podman container metadata
type Container struct {
	config *ContainerConfig
	state  *ContainerState
}

// ContainerConfig is a subset of the Podman's actual ContainerConfig
type ContainerConfig struct {
	ID           string `json:"id"`
	Pod          string `json:"pod,omitempty"`
	Namespace    string `json:"namespace,omitempty"`
	RawImageName string `json:"RawImageName,omitempty"`

	// embedded sub-configs
	ContainerRootFSConfig
	ContainerNetworkConfig
}

// ContainerRootFSConfig contains the info about podman's Rootfs
type ContainerRootFSConfig struct {
	RootfsImageID string `json:"rootfsImageID,omitempty"`
}

// ContainerNetworkConfig contains info about podman's ContainerNetworkConfig
type ContainerNetworkConfig struct {
	StaticIP     net.IP              `json:"staticIP,omitempty"`
	ExposedPorts map[uint16][]string `json:"exposedPorts,omitempty"`
}

// ContainerState contains info about podman's containers state
type ContainerState struct {
	State        ContainerStatus `json:"state"`
	StartedTime  time.Time       `json:"startedTime,omitempty"`
	FinishedTime time.Time       `json:"finishedTime,omitempty"`
	ExitCode     int32           `json:"exitCode,omitempty"`
	Exited       bool            `json:"exited,omitempty"`
	PID          int             `json:"pid,omitempty"`
}

// ContainerStatus represents the current state of a container
type ContainerStatus int

const (
	// ContainerStateUnknown indicates that the container is in an error
	// state where information about it cannot be retrieved
	ContainerStateUnknown ContainerStatus = iota
	// ContainerStateConfigured indicates that the container has had its
	// storage configured but it has not been created in the OCI runtime
	ContainerStateConfigured ContainerStatus = iota
	// ContainerStateCreated indicates the container has been created in
	// the OCI runtime but not started
	ContainerStateCreated ContainerStatus = iota
	// ContainerStateRunning indicates the container is currently executing
	ContainerStateRunning ContainerStatus = iota
	// ContainerStateStopped indicates that the container was running but has
	// exited
	ContainerStateStopped ContainerStatus = iota
	// ContainerStatePaused indicates that the container has been paused
	ContainerStatePaused ContainerStatus = iota
	// ContainerStateExited indicates the container has stopped and been
	// cleaned up
	ContainerStateExited ContainerStatus = iota
	// ContainerStateRemoving indicates the container is in the process of
	// being removed.
	ContainerStateRemoving ContainerStatus = iota
	// ContainerStateStopping indicates the container is in the process of
	// being stopped.
	ContainerStateStopping ContainerStatus = iota
)

// ContainerStatus returns a string representation for users of a container
// state. All results should match Docker's versions (from `docker ps`) as
// closely as possible, given the different set of states we support.
func (t ContainerStatus) String() string {
	switch t {
	case ContainerStateUnknown:
		return "unknown"
	case ContainerStateConfigured:
		// The naming here is confusing, but it's necessary for Docker
		// compatibility - their Created state is our Configured state.
		return "created"
	case ContainerStateCreated:
		// Docker does not have an equivalent to this state, so give it
		// a clear name. Most of the time this is a purely transitory
		// state between Configured and Running so we don't expect to
		// see it much anyways.
		return "initialized"
	case ContainerStateRunning:
		return "running"
	case ContainerStateStopped:
		return "stopped"
	case ContainerStatePaused:
		return "paused"
	case ContainerStateExited:
		return "exited"
	case ContainerStateRemoving:
		return "removing"
	case ContainerStateStopping:
		return "stopping"
	}
	return "bad state"
}
