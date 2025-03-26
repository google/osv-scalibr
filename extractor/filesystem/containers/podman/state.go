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
	"database/sql"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	_ "github.com/mattn/go-sqlite3"
	bolt "go.etcd.io/bbolt"
)

// subset of https://github.com/containers/podman/blob/main/libpod/state.go
type State interface {
	Close() error
	AllContainers() ([]*Container, error)
}

var _ State = &boltState{}

type boltState struct {
	conn *bolt.DB
}

func newBoltState(path string) (State, error) {
	db, err := bolt.Open(path, 0444, &bolt.Options{Timeout: 1 * time.Second})
	if err != nil {
		return nil, err
	}
	return &boltState{conn: db}, nil
}

// AllContainers return all the pods
func (s *boltState) AllContainers() ([]*Container, error) {
	ctrs := []*Container{}

	err := s.conn.View(func(tx *bolt.Tx) error {
		allCtrsBucket := tx.Bucket([]byte("all-ctrs"))
		if allCtrsBucket == nil {
			return fmt.Errorf("allCtrs bucket not found in DB")
		}

		ctrBuckets := tx.Bucket([]byte("ctr"))
		if ctrBuckets == nil {
			return fmt.Errorf("containers bucket not found in DB")
		}

		return allCtrsBucket.ForEach(func(id, name []byte) error {
			ctrBucket := ctrBuckets.Bucket(id)
			if ctrBucket == nil {
				return fmt.Errorf("state is inconsistent - container ID %s in all containers, but container not found", string(id))
			}

			ctr := new(Container)
			ctr.config = new(ContainerConfig)
			ctr.state = new(ContainerState)

			configBytes := ctrBucket.Get([]byte("config"))
			if err := json.Unmarshal(configBytes, ctr.config); err != nil {
				return fmt.Errorf("unmarshalling container %s config: %w", string(id), err)
			}

			stateBytes := ctrBucket.Get([]byte("state"))
			if err := json.Unmarshal(stateBytes, ctr.state); err != nil {
				return fmt.Errorf("unmarshalling container %s state: %w", string(id), err)
			}

			ctrs = append(ctrs, ctr)
			return nil
		})
	})
	if err != nil {
		return nil, err
	}

	return ctrs, nil
}

// Close closes the bolt db connection
func (b *boltState) Close() error {
	return b.conn.Close()
}

var _ State = &sqliteState{}

type sqliteState struct {
	conn *sql.DB
}

func newSqliteState(path string) (State, error) {
	db, err := sql.Open("sqlite3", path)
	if err != nil {
		return nil, err
	}
	return &sqliteState{conn: db}, nil
}

// AllContainers return all the pods
// see: https://github.com/containers/podman/blob/e65687291a1b59f98d6e41477f15171a384f93a0/libpod/sqlite_state.go#L820C23-L820C36
func (s *sqliteState) AllContainers() ([]*Container, error) {
	rows, err := s.conn.Query("SELECT ContainerConfig.JSON, ContainerState.JSON AS StateJSON FROM ContainerConfig INNER JOIN ContainerState ON ContainerConfig.ID = ContainerState.ID;")
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var ctrs []*Container
	for rows.Next() {
		var configJSON, stateJSON string
		if err := rows.Scan(&configJSON, &stateJSON); err != nil {
			return nil, fmt.Errorf("scanning container from database: %w", err)
		}

		ctr := new(Container)
		ctr.config = new(ContainerConfig)
		ctr.state = new(ContainerState)

		if err := json.Unmarshal([]byte(configJSON), ctr.config); err != nil {
			return nil, fmt.Errorf("unmarshalling container config: %w", err)
		}
		if err := json.Unmarshal([]byte(stateJSON), ctr.state); err != nil {
			return nil, fmt.Errorf("unmarshalling container %s state: %w", ctr.config.ID, err)
		}
		ctrs = append(ctrs, ctr)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return ctrs, nil
}

// Close closes the bolt db connection
func (s *sqliteState) Close() error {
	return s.conn.Close()
}

func getDBState(path string) (State, error) {
	switch {
	case strings.HasSuffix(path, "bolt_state.db"):
		return newBoltState(path)
	case strings.HasSuffix(path, "db.sql"):
		return newSqliteState(path)
	default:
		return nil, fmt.Errorf("cannot create state from %s, database not implemented", path)
	}
}
