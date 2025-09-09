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

// Package stripeapikey defines types representing different kinds of
// Stripe API keys and webhook secrets.
package stripeapikey

// StripeSKTestKey is a Veles Secret that holds a Stripe test secret key
// (prefixed with `sk_test_`).
type StripeSKTestKey struct {
	Key string
}

// StripeSKLiveKey is a Veles Secret that holds a Stripe live secret key
// (prefixed with `sk_live_`).
type StripeSKLiveKey struct {
	Key string
}

// StripeRKTestKey is a Veles Secret that holds a Stripe restricted test
// key (prefixed with `rk_test_`).
type StripeRKTestKey struct {
	Key string
}

// StripeRKLiveKey is a Veles Secret that holds a Stripe restricted live
// key (prefixed with `rk_live_`).
type StripeRKLiveKey struct {
	Key string
}

// StripeWebhookSecret is a Veles Secret that holds a Stripe webhook
// signing secret (prefixed with `whsec_`).
type StripeWebhookSecret struct {
	Key string
}
