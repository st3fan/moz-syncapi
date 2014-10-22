// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/

package syncapi

import (
	"crypto/dsa"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"github.com/gorilla/mux"
	"github.com/st3fan/gofxa/fxa"
	"github.com/st3fan/gowebtoken/webtoken"
	"github.com/st3fan/moz-syncapi/sync"
	"github.com/st3fan/moz-syncapi/tokenclient"
	"log"
	"net/http"
	"strings"
	"time"
)

const (
	ASSERTION_OFFSET   = time.Duration(15) * time.Second
	ASSERTION_DURATION = time.Duration(24*60*60) * time.Second
)

type Application struct {
	config Config
}

type Credentials struct {
	Username    string
	Password    string
	KeyA        []byte
	KeyB        []byte
	ApiEndpoint string
	ApiKeyId    string
	ApiKey      string
}

func generateRandomKey() (*dsa.PrivateKey, error) {
	params := new(dsa.Parameters)
	if err := dsa.GenerateParameters(params, rand.Reader, dsa.L1024N160); err != nil {
		return nil, err
	}
	priv := new(dsa.PrivateKey)
	priv.PublicKey.Parameters = *params
	if err := dsa.GenerateKey(priv, rand.Reader); err != nil {
		return nil, err
	}
	return priv, nil
}

func deriveClientStateFromKey(key []byte) string {
	hash := sha256.New()
	hash.Write(key)
	return hex.EncodeToString(hash.Sum(nil)[0:16])
}

func (app *Application) authenticate(w http.ResponseWriter, r *http.Request) *Credentials {
	// Grab the credentials from basic auth

	authorization := r.Header.Get("Authorization")
	if len(authorization) == 0 {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return nil
	}

	tokens := strings.SplitN(authorization, " ", 2)
	if len(tokens) != 2 {
		http.Error(w, "Unsupported authorization method", http.StatusUnauthorized)
		return nil
	}
	if tokens[0] != "Basic" {
		http.Error(w, "Unsupported authorization method", http.StatusUnauthorized)
		return nil
	}

	usernamePassword, err := base64.StdEncoding.DecodeString(tokens[1])
	if err != nil {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return nil
	}

	usernameAndPassword := strings.SplitN(string(usernamePassword), ":", 2)
	if len(usernameAndPassword) != 2 {
		http.Error(w, "authorization failed", http.StatusUnauthorized)
		return nil
	}

	// Do the FxA dance

	client, err := fxa.NewClient(usernameAndPassword[0], usernameAndPassword[1])
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return nil
	}

	if err := client.Login(); err != nil {
		http.Error(w, "Authorization failed: "+err.Error(), http.StatusUnauthorized)
		return nil
	}

	if err := client.FetchKeys(); err != nil {
		http.Error(w, "Authorization failed: "+err.Error(), http.StatusUnauthorized)
		return nil
	}

	key, err := generateRandomKey()
	if err != nil {
		log.Fatal("Could not generate DSA key: ", err)
	}

	cert, err := client.SignCertificate(key)
	if err != nil {
		http.Error(w, "Authorization failed: "+err.Error(), http.StatusUnauthorized)
		return nil
	}

	// Turn the certificate into an assertion

	issuedAt := time.Now().Add(-ASSERTION_OFFSET)
	expiresAt := issuedAt.Add(ASSERTION_DURATION)

	assertion, err := webtoken.CreateAssertion(*key, cert, "https://token.services.mozilla.com", "127.0.0.1", issuedAt, expiresAt)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return nil
	}

	// Send the certificate to the token server

	tokenClient, _ := tokenclient.New()
	tokenServerResponse, err := tokenClient.ExchangeToken(assertion, "sync", "1.5", deriveClientStateFromKey(client.KeyB))
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return nil
	}

	//

	return &Credentials{
		Username:    usernameAndPassword[0],
		Password:    usernameAndPassword[1],
		KeyA:        client.KeyA,
		KeyB:        client.KeyB,
		ApiEndpoint: tokenServerResponse.ApiEndpoint,
		ApiKeyId:    tokenServerResponse.Id,
		ApiKey:      tokenServerResponse.Key,
	}
}

//

func (app *Application) HandleProfile(w http.ResponseWriter, r *http.Request) {
	if credentials := app.authenticate(w, r); credentials != nil {
	}
}

func (app *Application) HandleTabs(w http.ResponseWriter, r *http.Request) {
	if credentials := app.authenticate(w, r); credentials != nil {
		storageClient, err := sync.NewStorageClient(credentials.ApiEndpoint, credentials.ApiKeyId, credentials.ApiKey, credentials.KeyB)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		keyBundle, err := storageClient.FetchKeys()
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		log.Print("KEY BUNDLE: ", keyBundle)
	}
}

//

func SetupRouter(r *mux.Router, config Config) (*Application, error) {
	app := &Application{config: config}
	r.HandleFunc("/1.0/profile", app.HandleProfile)
	r.HandleFunc("/1.0/tabs", app.HandleTabs)
	return app, nil
}
