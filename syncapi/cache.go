// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/

package syncapi

import (
	"sync"
	"time"
)

type CredentialsCacheEntry struct {
	Credentials Credentials
	Expires     time.Time
}

func (e *CredentialsCacheEntry) IsExpired() bool {
	return time.Now().After(e.Expires)
}

type CredentialsCache struct {
	sync.Mutex
	Entries map[string]CredentialsCacheEntry
}

func NewCredentialsCache(ttl time.Duration) *CredentialsCache {
	return &CredentialsCache{
		Entries: map[string]CredentialsCacheEntry{},
	}
}

func (cc *CredentialsCache) Get(username, password string) (Credentials, bool) {
	cc.Lock()
	defer cc.Unlock()
	cacheEntry, ok := cc.Entries[username+":"+password]
	if ok {
		if cacheEntry.IsExpired() {
			delete(cc.Entries, username+":"+password)
			return Credentials{}, false
		}
	}
	return cacheEntry.Credentials, ok
}

func (cc *CredentialsCache) Put(credentials Credentials, duration time.Duration) {
	cc.Lock()
	cc.Entries[credentials.Username+":"+credentials.Password] = CredentialsCacheEntry{
		Credentials: credentials,
		Expires:     time.Now().Add(duration),
	}
	cc.Unlock()
}
