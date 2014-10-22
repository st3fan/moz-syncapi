// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/

package tokenclient

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"net/http"
)

type TokenClient struct {
}

type TokenServerResponse struct {
	Id          string `json:"id"`           // Signed authorization token
	Key         string `json:"key"`          // Secret derived from the shared secret
	Uid         uint64 `json:"uid"`          // The user id for this service
	ApiEndpoint string `json:"api_endpoint"` // The root URL for the user of this service
	Duration    int64  `json:"duration"`     // the validity duration of the issued token, in seconds
}

func New() (*TokenClient, error) {
	return &TokenClient{}, nil
}

func (tc *TokenClient) ExchangeToken(assertion, service, version, clientState string) (*TokenServerResponse, error) {
	url := fmt.Sprintf("https://token.services.mozilla.com/1.0/%s/%s", service, version)

	client := &http.Client{}

	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "BrowserID "+assertion)
	req.Header.Set("Accept", "application/json")
	req.Header.Set("X-Client-State", clientState)

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

	tokenServerResponse := &TokenServerResponse{}
	if err = json.Unmarshal(body, tokenServerResponse); err != nil {
		return nil, err
	}

	return tokenServerResponse, nil
}
