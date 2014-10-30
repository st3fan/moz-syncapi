// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/

package sync

import (
	"bytes"
	"code.google.com/p/go.crypto/hkdf"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"github.com/st3fan/gofxa/fxa"
	"io"
	"io/ioutil"
	"log"
	"net/http"
	"strconv"
)

const USER_AGENT = "SyncAPI/0.1 (https://github.com/st3fan/moz-syncapi)"

//

type KeyBundle struct {
	EncryptionKey []byte
	ValidationKey []byte
}

func NewKeyBundle(key []byte) (*KeyBundle, error) {
	secret := make([]byte, 2*32)
	if _, err := io.ReadFull(hkdf.New(sha256.New, key, nil, []byte("identity.mozilla.com/picl/v1/oldsync")), secret); err != nil {
		return nil, err
	}
	return &KeyBundle{
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
	keyBundle KeyBundle
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
	req.Header.Set("User-Agent", USER_AGENT)

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

func (sc *StorageClient) GetEncryptedRecord(collectionName, recordId string, keyBundle *KeyBundle) (Record, error) {
	record, err := sc.GetRecord(collectionName, recordId)
	if err != nil {
		return Record{}, err
	}

	if keyBundle == nil {
		keyBundle = &sc.keyBundle
	}

	if err := record.Decrypt(keyBundle); err != nil {
		return Record{}, err
	}

	return record, nil
}

type GetRecordsOptions struct {
	Limit int
	Sort  string
}

func (sc *StorageClient) GetEncryptedRecords(collectionName string, keyBundle *KeyBundle, options *GetRecordsOptions) ([]Record, error) {
	url := sc.endpoint + "/storage/" + collectionName + "?full=1"
	if options != nil {
		if options.Limit != 0 {
			url += "&limit=" + strconv.Itoa(options.Limit)
		}
		if options.Sort != "" {
			url += "&sort=" + options.Sort
		}
	}

	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, err
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", USER_AGENT)

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

	if keyBundle == nil {
		keyBundle = &sc.keyBundle
	}

	for i := 0; i < len(records); i++ {
		if err := records[i].Decrypt(keyBundle); err != nil {
			return nil, err
		}
	}

	return records, nil
}

func (sc *StorageClient) Login() error {
	keyBundle, err := sc.FetchKeys()
	if err != nil {
		return err
	}
	sc.keyBundle = keyBundle
	return nil
}

func (sc *StorageClient) PutEncryptedRecord(collectionName string, record Record, keyBundle *KeyBundle) (string, error) {
	if keyBundle == nil {
		keyBundle = &sc.keyBundle
	}

	if err := record.Encrypt(keyBundle); err != nil {
		return "", err
	}

	encodedRecord, err := json.Marshal(&record)
	if err != nil {
		return "", err
	}

	// Upload the record

	url := sc.endpoint + "/storage/" + collectionName + "/" + record.Id

	client := &http.Client{}

	req, err := http.NewRequest("PUT", url, bytes.NewReader(encodedRecord))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", USER_AGENT)

	hawkCredentials := fxa.NewHawkCredentials(sc.hawkKeyId, []byte(sc.hawkKey))
	if err := hawkCredentials.AuthorizeRequest(req, bytes.NewReader(encodedRecord), ""); err != nil {
		return "", err
	}

	res, err := client.Do(req)
	if err != nil {
		return "", err
	}

	if res.StatusCode != http.StatusOK {
		return "", errors.New(res.Status) // TODO: Proper errors based on what the server returns
	}

	return record.Id, nil
}
