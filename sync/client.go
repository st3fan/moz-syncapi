// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/

package sync

import (
	"bytes"
	"code.google.com/p/go.crypto/hkdf"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"github.com/st3fan/gofxa/fxa"
	"io"
	"io/ioutil"
	"net/http"
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

func (r *Record) Decrypt(keyBundle KeyBundle) error {
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

//

type KeyBundle struct {
	EncryptionKey []byte
	ValidationKey []byte
}

func NewKeyBundle(key []byte) (KeyBundle, error) {
	secret := make([]byte, 2*32)
	if _, err := io.ReadFull(hkdf.New(sha256.New, key, nil, []byte("identity.mozilla.com/picl/v1/oldsync")), secret); err != nil {
		return KeyBundle{}, err
	}
	return KeyBundle{
		EncryptionKey: secret[0:32],
		ValidationKey: secret[32:64],
	}, nil
}

//

type StorageClient struct {
	endpoint  string
	hawkKeyId string
	hawkKey   string
	secret    []byte
}

func NewStorageClient(endpoint, hawkKeyId, hawkKey string, secret []byte) (*StorageClient, error) {
	return &StorageClient{
		endpoint:  endpoint,
		hawkKeyId: hawkKeyId,
		hawkKey:   hawkKey,
		secret:    secret,
	}, nil
}

type KeysPayload struct {
	Default []string `json:"default"`
}

func (sc *StorageClient) FetchKeys() (KeyBundle, error) {
	globalKeyBundle, err := NewKeyBundle(sc.secret)
	if err != nil {
		return KeyBundle{}, err
	}

	record, err := sc.GetEncryptedRecord("crypto", "keys", globalKeyBundle)
	if err != nil {
		return KeyBundle{}, err
	}

	keysPayload := KeysPayload{}
	if err = json.Unmarshal([]byte(record.Payload), &keysPayload); err != nil {
		return KeyBundle{}, err
	}

	encryptionKey, err := base64.StdEncoding.DecodeString(keysPayload.Default[0])
	if err != nil {
		return KeyBundle{}, err
	}

	validationKey, err := base64.StdEncoding.DecodeString(keysPayload.Default[1])
	if err != nil {
		return KeyBundle{}, err
	}

	return KeyBundle{
		EncryptionKey: encryptionKey,
		ValidationKey: validationKey,
	}, nil
}

func (sc *StorageClient) GetRecord(collectionName, recordId string) (Record, error) {
	req, err := http.NewRequest("GET", sc.endpoint+"/storage/"+collectionName+"/"+recordId, nil)
	if err != nil {
		return Record{}, err
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")

	hawkCredentials := fxa.NewHawkCredentials(sc.hawkKeyId, []byte(sc.hawkKey))
	if err := hawkCredentials.AuthorizeRequest(req, nil, ""); err != nil {
		return Record{}, err
	}

	client := &http.Client{}
	res, err := client.Do(req)
	if err != nil {
		return Record{}, err
	}
	defer res.Body.Close()

	body, err := ioutil.ReadAll(res.Body)
	if err != nil {
		return Record{}, err
	}

	if res.StatusCode != http.StatusOK {
		return Record{}, errors.New(res.Status) // TODO: Proper errors based on what the server returns
	}

	record := Record{}
	if err = json.Unmarshal(body, &record); err != nil {
		return Record{}, err
	}

	return record, nil
}

func (sc *StorageClient) GetEncryptedRecord(collectionName, recordId string, keyBundle KeyBundle) (Record, error) {
	record, err := sc.GetRecord(collectionName, recordId)
	if err != nil {
		return Record{}, err
	}

	if err := record.Decrypt(keyBundle); err != nil {
		return Record{}, err
	}

	return record, nil
}

func (sc *StorageClient) GetEncryptedRecords(collectionName string, keyBundle KeyBundle) ([]Record, error) {
	req, err := http.NewRequest("GET", sc.endpoint+"/storage/"+collectionName+"?full=1", nil)
	if err != nil {
		return nil, err
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")

	hawkCredentials := fxa.NewHawkCredentials(sc.hawkKeyId, []byte(sc.hawkKey))
	if err := hawkCredentials.AuthorizeRequest(req, nil, ""); err != nil {
		return nil, err
	}

	client := &http.Client{}
	res, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer res.Body.Close()

	body, err := ioutil.ReadAll(res.Body)
	if err != nil {
		return nil, err
	}

	if res.StatusCode != http.StatusOK {
		return nil, errors.New(res.Status) // TODO: Proper errors based on what the server returns
	}

	records := []Record{}
	if err = json.Unmarshal(body, &records); err != nil {
		return nil, err
	}

	for i := 0; i < len(records); i++ {
		if err := records[i].Decrypt(keyBundle); err != nil {
			return nil, err
		}
	}

	return records, nil
}
