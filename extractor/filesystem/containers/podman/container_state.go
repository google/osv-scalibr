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

import "time"

type ContainerState struct {
	State            ContainerStatus `json:"state"`
	ConfigPath       string          `json:"configPath,omitempty"`
	RunDir           string          `json:"runDir,omitempty"`
	Mounted          bool            `json:"mounted,omitempty"`
	Mountpoint       string          `json:"mountPoint,omitempty"`
	StartedTime      time.Time       `json:"startedTime,omitempty"`
	FinishedTime     time.Time       `json:"finishedTime,omitempty"`
	ExitCode         int32           `json:"exitCode,omitempty"`
	Exited           bool            `json:"exited,omitempty"`
	Error            string          `json:"error,omitempty"`
	OOMKilled        bool            `json:"oomKilled,omitempty"`
	Checkpointed     bool            `json:"checkpointed,omitempty"`
	PID              int             `json:"pid,omitempty"`
	ConmonPID        int             `json:"conmonPid,omitempty"`
	CheckpointedTime time.Time       `json:"checkpointedTime,omitempty"`
	RestoredTime     time.Time       `json:"restoredTime,omitempty"`
	CheckpointLog    string          `json:"checkpointLog,omitempty"`
	CheckpointPath   string          `json:"checkpointPath,omitempty"`
	RestoreLog       string          `json:"restoreLog,omitempty"`
	Restored         bool            `json:"restored,omitempty"`
}
