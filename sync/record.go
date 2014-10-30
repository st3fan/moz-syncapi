// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/

package sync

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
)

type EncryptedPayload struct {
	CipherText string `json:"ciphertext"`
	IV         string `json:"IV"`
	HMAC       string `json:"HMAC"`
}

type Record struct {
	Id       string  `json:"id"`
	Modified float64 `json:"modified"`
	Payload  string  `json:"payload"`
}

func (r *Record) Encrypt(keyBundle *KeyBundle) error {

	// Encrypt the original payload

	iv := make([]byte, aes.BlockSize)
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		return err
	}

	block, err := aes.NewCipher(keyBundle.EncryptionKey)
	if err != nil {
		return err
	}

	plaintext := paddedPlaintext([]byte(r.Payload), aes.BlockSize)
	ciphertext := make([]byte, len(plaintext))

	mode := cipher.NewCBCEncrypter(block, iv)
	mode.CryptBlocks(ciphertext, plaintext)

	encodedCiphertext := base64.StdEncoding.EncodeToString(ciphertext)

	// HMAC

	mac := hmac.New(sha256.New, keyBundle.ValidationKey)
	mac.Write([]byte(encodedCiphertext))
	hash := mac.Sum(nil)

	// Create a new payload

	encryptedPayload := EncryptedPayload{
		CipherText: encodedCiphertext,
		IV:         base64.StdEncoding.EncodeToString(iv),
		HMAC:       hex.EncodeToString(hash),
	}

	encodedPayload, err := json.Marshal(&encryptedPayload)
	if err != nil {
		return err
	}

	r.Payload = string(encodedPayload)

	return nil
}

func (r *Record) Decrypt(keyBundle *KeyBundle) error {
	encryptedPayload := &EncryptedPayload{}
	if err := json.Unmarshal([]byte(r.Payload), encryptedPayload); err != nil {
		return errors.New("Record does not have an encrypted payload")
	}

	HMAC, err := hex.DecodeString(encryptedPayload.HMAC)
	if err != nil {
		return errors.New("Malformed HMAC in record")
	}

	// Verify the payload

	mac := hmac.New(sha256.New, keyBundle.ValidationKey)
	mac.Write([]byte(encryptedPayload.CipherText))
	if !bytes.Equal(mac.Sum(nil), HMAC) {
		return errors.New("Record validation failed")
	}

	// Decrypt the payload

	ciphertext, err := base64.StdEncoding.DecodeString(encryptedPayload.CipherText)
	if err != nil {
		return errors.New("Malformed ciphertext in record")
	}

	iv, err := base64.StdEncoding.DecodeString(encryptedPayload.IV)
	if err != nil {
		return errors.New("Malformed IV in record")
	}

	block, err := aes.NewCipher(keyBundle.EncryptionKey)
	if err != nil {
		return err
	}

	mode := cipher.NewCBCDecrypter(block, iv)
	mode.CryptBlocks(ciphertext, ciphertext)

	// TODO: Is there a stdlib something to deal with PKCS7 padding?
	length := len(ciphertext)
	unpadding := int(ciphertext[length-1])
	ciphertext = ciphertext[:(length - unpadding)]

	r.Payload = string(ciphertext)

	return nil
}
