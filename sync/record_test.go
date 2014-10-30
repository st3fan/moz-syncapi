// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/

package sync

import (
	"testing"
)

func Test_Record_EncryptDecrypt(t *testing.T) {
	payload := "This is some payload"

	record := Record{
		Id:       "1234567890AB",
		Modified: 123456789.0,
		Payload:  payload,
	}

	keyBundle, err := NewKeyBundle([]byte{0xd0, 0x2d, 0x8f, 0xe3, 0x9f, 0x28, 0xb6, 0x01, 0x15, 0x9c, 0x54, 0x3f, 0x2d, 0xee, 0xb8, 0xf7, 0x2b, 0xdf, 0x20, 0x43, 0xe8, 0x27, 0x9a, 0xa0, 0x84, 0x96, 0xfb, 0xd9, 0xeb, 0xae, 0xa3, 0x61})
	if err != nil {
		t.Error(err)
	}

	if err := record.Encrypt(keyBundle); err != nil {
		t.Error(err)
	}

	if record.Payload == payload {
		t.Error("Payload did not encrypt")
	}

	if err := record.Decrypt(keyBundle); err != nil {
		t.Error(err)
	}

	if record.Payload != payload {
		t.Error("Payload did not decrypt")
	}
}
