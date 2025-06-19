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

package veles

import (
	"context"
	"errors"
	"fmt"
	"io"
)

const (
	// KiB is one binary Kilobyte (Kibibyte) i.e. 1024 bytes.
	KiB = 1 << 10
	// MiB is one binary Megabyte (Mibibyte).
	MiB = 1 << 20
	// GiB is one binary Gigabyte (Gibibyte).
	GiB = 1 << 30

	// MinReadLen is the minimum buffer size for reading chunks from an io.Reader.
	MinReadLen = 64 * KiB

	// MinRetainLen is the minimum number of bytes from the end of a chunk to
	// retain to avoid false negatives from Secrets overlapping the edge of two
	// chunks.
	MinRetainLen = 1 * KiB
)

// Detector finds instances of Secrets inside a chunk of text.
//
// While most commonly a detector will emit one specific type of secret, we also
// allow for Detectors to return multiple distinct types - thus the []Secret
// return type.
type Detector interface {
	// MaxSecretLen is the maximum length a secret from this detector can have.
	//
	// It can be set to 0 but then the detector isn't guaranteed any minimum input
	// length and should instead implement its own mechanism to ensure it can find
	// its secrets; i.e. maintain an internal buffer.
	MaxSecretLen() uint32
	// Detect finds Secrets inside data and returns them alongside indices to the
	// start of the corresponding match.
	// The latter is only used internally to avoid duplicates.
	Detect(data []byte) ([]Secret, []int)
}

// DetectionEngine combines multiple Veles Detectors into a single engine that
// can read from an io.Reader. It outputs the results of applying all Detectors
// to that stream.
//
// Future optimizations might change how the engine works under the hood but its
// API should stay stable. It makes no guarantee about the order in which
// Secrets are found so calling code should not depend on it.
type DetectionEngine struct {
	ds []Detector

	// readLen is the buffer size used for reading chunks from an io.Reader.
	readLen int

	// retainLen is the buffer size used for keeping parts of a previous read
	// to avoid false negatives at the edge of two neighboring chunks.
	retainLen int
}

// DetectionEngineOption is an option to configure a DetectionEngine during
// creation via NewDetectionEngine.
//
// This allows user to fine tune the engine by overriding its defaults. For most
// use-cases, the defaults should be sensible enough.
type DetectionEngineOption func(*DetectionEngine)

// WithReadLen overrides the buffer size used for reading chunks from io.Reader.
//
// The value can be smaller than MinReadLen.
func WithReadLen(readLen uint32) DetectionEngineOption {
	return func(e *DetectionEngine) {
		e.readLen = int(readLen)
	}
}

// WithRetainLen overrides the buffer size used for keeping parts of a previous
// read to avoid false negatives at the edge of two neighboring chunks.
//
// These should usually be small against readLen. While it's technically
// possible to have retainLen > readLen, that doesn't make a lot of semantic
// sense and should be avoided.
func WithRetainLen(retainLen uint32) DetectionEngineOption {
	return func(e *DetectionEngine) {
		e.retainLen = int(retainLen)
	}
}

// NewDetectionEngine creates a new DetectionEngine with the given Detectors.
//
// This will choose sensible defaults for the internal buffers but those can
// be overridden via DetectionEngineOptions if needed.
//
// Returns an error if no detectors are provided or if the retain buffer would
// be too small to accommodate the detectors.
func NewDetectionEngine(ds []Detector, opts ...DetectionEngineOption) (*DetectionEngine, error) {
	if len(ds) == 0 {
		return nil, errors.New("cannot create DetectionEngine without Detectors")
	}
	maxSecretLen := uint32(0)
	for _, d := range ds {
		m := d.MaxSecretLen()
		if m > maxSecretLen {
			maxSecretLen = m
		}
	}
	defaultLen := int(nextPowerOf2(maxSecretLen))
	e := &DetectionEngine{
		ds:        ds,
		readLen:   max(MinReadLen, defaultLen),
		retainLen: max(MinRetainLen, defaultLen),
	}
	for _, opt := range opts {
		opt(e)
	}
	if e.retainLen < int(maxSecretLen) {
		return nil, fmt.Errorf("cannot create detection engine with retainLen (%d) < max secret len (%d)", e.retainLen, maxSecretLen)
	}
	return e, nil
}

// Detect reads from an io.Reader and returns the results of applying all of the
// DetectionEngine's Detectors to that stream.
//
// It reads the input stream in chunks making sure that no matches are
// accidentally missed at the edges between chunks.
//
// The secrets are returned in no particular order and calling code should not
// depend on it (hyrumslaw.com).
//
// An error is returned if the provided context is done or if the io.Reader
// returned any error other than io.EOF.
func (e *DetectionEngine) Detect(ctx context.Context, r io.Reader) ([]Secret, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	buf := make([]byte, 0, e.readLen+e.retainLen)
	// Fill up the entire buffer on the first Read. This is the only time the
	// engine reads more than readLen at once.
	n, err := io.ReadFull(r, buf[:cap(buf)])
	if err != nil {
		if !isEOF(err) {
			return nil, err
		}
		// Reader is already exhausted. No deduplication needed.
		return e.detectAll(buf[:n]), nil
	}
	secrets := e.detectLeft(buf[:cap(buf)])
	for {
		if err := ctx.Err(); err != nil {
			return secrets, err
		}
		// At this point the buffer is filled up to its cap because of io.ReadFull.
		// We retain the last e.retainLen bytes from the end and read in another
		// chunk of e.readLen.
		copy(buf[:e.retainLen], buf[e.readLen:cap(buf)])
		n, err := io.ReadFull(r, buf[e.retainLen:cap(buf)])
		if err != nil {
			if !isEOF(err) {
				return nil, err
			}
			secrets = append(secrets, e.detectRight(buf[:e.retainLen+n])...)
			break
		}
		secrets = append(secrets, e.detectMiddle(buf[:cap(buf)])...)
	}
	return secrets, nil
}

// detectAll returns all instances of Secrets inside the entire data buffer
// found by the Engine's Detectors.
func (e *DetectionEngine) detectAll(data []byte) []Secret {
	var secrets []Secret
	for _, d := range e.ds {
		ss, _ := d.Detect(data)
		secrets = append(secrets, ss...)
	}
	return secrets
}

// detectLeft returns all instances of Secrets inside the left part of the data
// buffer that begin at a position before d.MaxSecretLen from the end for each
// Detector d.
func (e *DetectionEngine) detectLeft(data []byte) []Secret {
	var secrets []Secret
	for _, d := range e.ds {
		right := len(data) - int(d.MaxSecretLen())
		ss, ps := d.Detect(data)
		for i, s := range ss {
			p := ps[i]
			if p >= right {
				continue
			}
			secrets = append(secrets, s)
		}
	}
	return secrets
}

// detectRight returns all instances of Secrets inside in the right part of the
// data buffer at a position greater than the respective Detector's
// MaxSecretLen.
// This is only ever called with len(data) >= d.MaxSecretLen() for all d.
func (e *DetectionEngine) detectRight(data []byte) []Secret {
	var secrets []Secret
	for _, d := range e.ds {
		left := e.retainLen - int(d.MaxSecretLen())
		ss, _ := d.Detect(data[left:])
		secrets = append(secrets, ss...)
	}
	return secrets
}

// detectMiddle returns all instances of Secrets inside the data buffer coming
// from the relevant window for each respective Detector.
// The relevant window is the section of data that contains no redundant Secrets
// for a given detector: i.e. only consider MaxSecretLen to the left and ignore
// secrets that start after MaxSecretLen from the right.
func (e *DetectionEngine) detectMiddle(data []byte) []Secret {
	var secrets []Secret
	for _, d := range e.ds {
		left := e.retainLen - int(d.MaxSecretLen())
		right := len(data) - left - int(d.MaxSecretLen())
		ss, ps := d.Detect(data[left:])
		for i, s := range ss {
			p := ps[i]
			if p >= right {
				continue
			}
			secrets = append(secrets, s)
		}
	}
	return secrets
}

func nextPowerOf2(x uint32) uint32 {
	x--
	x |= x >> 1
	x |= x >> 2
	x |= x >> 4
	x |= x >> 8
	x |= x >> 16
	x++
	return x
}

func isEOF(err error) bool {
	return errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF)
}
