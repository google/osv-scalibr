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

//go:build linux

package podman

import (
	"net"
	"time"
)

// container struct contains the podman container metadata
type container struct {
	config *containerConfig
	state  *containerState
}

// containerConfig is a subset of the Podman's actual containerConfig
type containerConfig struct {
	// embedded sub-configs
	containerRootFSConfig
	containerNetworkConfig

	ID           string `json:"id"`
	Pod          string `json:"pod,omitempty"`
	Namespace    string `json:"namespace,omitempty"`
	RawImageName string `json:"RawImageName,omitempty"`
}

// containerRootFSConfig contains the info about podman's Rootfs
type containerRootFSConfig struct {
	RootfsImageID string `json:"rootfsImageID,omitempty"`
}

// containerNetworkConfig contains info about podman's containerNetworkConfig
type containerNetworkConfig struct {
	StaticIP     net.IP              `json:"staticIP,omitempty"`
	ExposedPorts map[uint16][]string `json:"exposedPorts,omitempty"`
}

// containerState contains info about podman's containers state
type containerState struct {
	State        containerStatus `json:"state"`
	StartedTime  time.Time       `json:"startedTime,omitempty"`
	FinishedTime time.Time       `json:"finishedTime,omitempty"`
	ExitCode     int32           `json:"exitCode,omitempty"`
	Exited       bool            `json:"exited,omitempty"`
	PID          int             `json:"pid,omitempty"`
}

// containerStatus represents the current state of a container
type containerStatus int

// The numbers in the enums correspond to the integer values from the sqliteDB/boltDB
const (
	// containerStateUnknown indicates that the container is in an error
	// state where information about it cannot be retrieved
	containerStateUnknown containerStatus = 0
	// containerStateConfigured indicates that the container has had its
	// storage configured but it has not been created in the OCI runtime
	containerStateConfigured containerStatus = 1
	// containerStateCreated indicates the container has been created in
	// the OCI runtime but not started
	containerStateCreated containerStatus = 2
	// containerStateRunning indicates the container is currently executing
	containerStateRunning containerStatus = 3
	// containerStateStopped indicates that the container was running but has
	// exited
	containerStateStopped containerStatus = 4
	// containerStatePaused indicates that the container has been paused
	containerStatePaused containerStatus = 5
	// containerStateExited indicates the container has stopped and been
	// cleaned up
	containerStateExited containerStatus = 6
	// containerStateRemoving indicates the container is in the process of
	// being removed.
	containerStateRemoving containerStatus = 7
	// containerStateStopping indicates the container is in the process of
	// being stopped.
	containerStateStopping containerStatus = 8
)

// String returns a string representation for users of a container state.
func (t containerStatus) String() string {
	switch t {
	case containerStateUnknown:
		return "unknown"
	case containerStateConfigured:
		// The naming here is confusing, but it's necessary for Docker
		// compatibility - their Created state is our Configured state.
		return "created"
	case containerStateCreated:
		// Docker does not have an equivalent to this state, so give it
		// a clear name. Most of the time this is a purely transitory
		// state between Configured and Running so we don't expect to
		// see it much anyways.
		return "initialized"
	case containerStateRunning:
		return "running"
	case containerStateStopped:
		return "stopped"
	case containerStatePaused:
		return "paused"
	case containerStateExited:
		return "exited"
	case containerStateRemoving:
		return "removing"
	case containerStateStopping:
		return "stopping"
	}
	return "bad state"
}
