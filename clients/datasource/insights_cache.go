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

package datasource

import (
	"time"

	pb "deps.dev/api/v3"
	"google.golang.org/protobuf/proto"
)

type depsdevAPICache struct {
	Timestamp         *time.Time
	PackageCache      map[packageKey][]byte
	VersionCache      map[versionKey][]byte
	RequirementsCache map[versionKey][]byte
}

func protoMarshalCache[K comparable, V proto.Message](protoMap map[K]V) (map[K][]byte, error) {
	byteMap := make(map[K][]byte)
	for k, v := range protoMap {
		b, err := proto.Marshal(v)
		if err != nil {
			return nil, err
		}
		byteMap[k] = b
	}

	return byteMap, nil
}

func protoUnmarshalCache[K comparable, V any, PV interface {
	proto.Message
	*V
}](byteMap map[K][]byte, protoMap *map[K]PV) error {
	*protoMap = make(map[K]PV)
	for k, b := range byteMap {
		v := PV(new(V))
		if err := proto.Unmarshal(b, v); err != nil {
			return err
		}
		(*protoMap)[k] = v
	}

	return nil
}

// GobEncode encodes cache to bytes.
func (c *CachedInsightsClient) GobEncode() ([]byte, error) {
	var cache depsdevAPICache
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.cacheTimestamp == nil {
		now := time.Now().UTC()
		c.cacheTimestamp = &now
	}

	cache.Timestamp = c.cacheTimestamp
	var err error
	cache.PackageCache, err = protoMarshalCache(c.packageCache.GetMap())
	if err != nil {
		return nil, err
	}
	cache.VersionCache, err = protoMarshalCache(c.versionCache.GetMap())
	if err != nil {
		return nil, err
	}
	cache.RequirementsCache, err = protoMarshalCache(c.requirementsCache.GetMap())
	if err != nil {
		return nil, err
	}

	return gobMarshal(cache)
}

// GobDecode decodes bytes to cache.
func (c *CachedInsightsClient) GobDecode(b []byte) error {
	var cache depsdevAPICache
	if err := gobUnmarshal(b, &cache); err != nil {
		return err
	}

	if cache.Timestamp != nil && time.Since(*cache.Timestamp) >= cacheExpiry {
		// Cache expired
		return nil
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	c.cacheTimestamp = cache.Timestamp

	var pkgMap map[packageKey]*pb.Package
	if err := protoUnmarshalCache(cache.PackageCache, &pkgMap); err != nil {
		return err
	}

	var verMap map[versionKey]*pb.Version
	if err := protoUnmarshalCache(cache.VersionCache, &verMap); err != nil {
		return err
	}

	var reqMap map[versionKey]*pb.Requirements
	if err := protoUnmarshalCache(cache.RequirementsCache, &reqMap); err != nil {
		return err
	}

	c.packageCache.SetMap(pkgMap)
	c.versionCache.SetMap(verMap)
	c.requirementsCache.SetMap(reqMap)

	return nil
}
