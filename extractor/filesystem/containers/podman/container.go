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

// see
// - https://github.com/containers/podman/blob/e65687291a1b59f98d6e41477f15171a384f93a0/libpod/container.go
// - https://github.com/containers/podman/blob/e65687291a1b59f98d6e41477f15171a384f93a0/libpod/container_config.go
// - https://github.com/containers/podman/blob/e65687291a1b59f98d6e41477f15171a384f93a0/libpod/define/containerstate.go

type Container struct {
	config *ContainerConfig
	state  *ContainerState
}
