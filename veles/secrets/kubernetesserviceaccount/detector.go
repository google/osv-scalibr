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

// Package kubernetesserviceaccount contains the logic to detect Kubernetes
// ServiceAccount tokens, which are JWT tokens containing Kubernetes-specific
// claims.
package kubernetesserviceaccount

import (
	"github.com/google/osv-scalibr/veles"
	"github.com/google/osv-scalibr/veles/secrets/common/jwt"
)

type detector struct{}

// NewDetector returns a new Veles Detector that finds Kubernetes ServiceAccount
// tokens.
func NewDetector() veles.Detector {
	return &detector{}
}

// Detect finds Kubernetes ServiceAccount tokens.
func (d *detector) Detect(data []byte) ([]veles.Secret, []int) {
	tokens, positions := jwt.ExtractTokens(data)
	var secrets []veles.Secret
	var secretPositions []int
	for i, t := range tokens {
		if isKubernetesServiceAccountToken(t) {
			secrets = append(secrets, Token{Value: t.Raw()})
			secretPositions = append(secretPositions, positions[i])
		}
	}
	return secrets, secretPositions
}

// MaxSecretLen returns the max length that a Kubernetes ServiceAccount token
// can have. Kubernetes ServiceAccount tokens are JWTs, so we use the same
// limit as the JWT detector.
func (d *detector) MaxSecretLen() uint32 {
	return jwt.MaxTokenLength
}

// isKubernetesServiceAccountToken checks whether a JWT token contains the
// Kubernetes ServiceAccount-specific claims.
func isKubernetesServiceAccountToken(t jwt.Token) bool {
	payload := t.Payload()
	if payload == nil {
		return false
	}
	// Kubernetes ServiceAccount tokens contain at least one of these claims.
	kubernetesClaims := []string{
		"kubernetes.io/serviceaccount/namespace",
		"kubernetes.io/serviceaccount/service-account.name",
		"kubernetes.io/serviceaccount/service-account.uid",
	}
	for _, claim := range kubernetesClaims {
		if _, ok := payload[claim]; ok {
			return true
		}
	}
	return false
}
