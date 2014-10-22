// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/

package syncapi

const (
	DEFAULT_PERSONA_VERIFIER = "https://verifier.accounts.firefox.com/v2"
)

type Config struct {
	PersonaVerifier string
}

func DefaultConfig() Config {
	return Config{
		PersonaVerifier: DEFAULT_PERSONA_VERIFIER,
	}
}
