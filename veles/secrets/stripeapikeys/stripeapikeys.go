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

// Copyright 2025 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// Package stripeapikeys contains detectors and validators for
// Stripe API credentials.
package stripeapikeys

// StripeSecretKey is a Veles Secret that holds a Stripe Secret Key (sk_live_...).
type StripeSecretKey struct {
	Key string
}

// StripeRestrictedKey is a Veles Secret that holds a Stripe Restricted Key (rk_live_...).
type StripeRestrictedKey struct {
	Key string
}

// StripeWebhookSecret is a Veles Secret that holds a Stripe Webhook Signing Secret (whsec_...).
type StripeWebhookSecret struct {
	Key string
}
