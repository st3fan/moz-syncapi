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
	"encoding/json"
	"github.com/gorilla/mux"
	"github.com/st3fan/gofxa/fxa"
	"github.com/st3fan/gowebtoken/webtoken"
	"github.com/st3fan/moz-syncapi/sync"
	"github.com/st3fan/moz-syncapi/tokenclient"
	"log"
	"net/http"
	"sort"
	"strings"
	"time"
)

const (
	CREDENTIALS_CACHE_TTL = time.Duration(24*60*60) * time.Second
	ASSERTION_OFFSET      = time.Duration(15) * time.Second
	ASSERTION_DURATION    = time.Duration(24*60*60) * time.Second
)

type Application struct {
	config           Config
	credentialsCache *CredentialsCache
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

func requireBasicAuth(w http.ResponseWriter, message string) {
	w.Header().Set("WWW-Authenticate", `Basic realm="API"`)
	w.WriteHeader(401)
	w.Write([]byte("401 " + message + "\n"))
}

func (app *Application) authenticate(w http.ResponseWriter, r *http.Request) *Credentials {
	// Grab the credentials from basic auth

	authorization := r.Header.Get("Authorization")
	if len(authorization) == 0 {
		requireBasicAuth(w, "Authorization Required")
		return nil
	}

	tokens := strings.SplitN(authorization, " ", 2)
	if len(tokens) != 2 {
		requireBasicAuth(w, "Invalid Authorization Header (Truncated)")
		return nil
	}
	if tokens[0] != "Basic" {
		requireBasicAuth(w, "Invalid Authorization Header (Method not Basic)")
		return nil
	}

	usernamePassword, err := base64.StdEncoding.DecodeString(tokens[1])
	if err != nil {
		requireBasicAuth(w, "Invalid Authorization Header (Failed to decode credentials)")
		return nil
	}

	usernameAndPassword := strings.SplitN(string(usernamePassword), ":", 2)
	if len(usernameAndPassword) != 2 {
		http.Error(w, "authorization failed", http.StatusUnauthorized)
		return nil
	}

	credentials, ok := app.credentialsCache.Get(usernameAndPassword[0], usernameAndPassword[1])
	if ok {
		return &credentials
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

	credentials = Credentials{
		Username:    usernameAndPassword[0],
		Password:    usernameAndPassword[1],
		KeyA:        client.KeyA,
		KeyB:        client.KeyB,
		ApiEndpoint: tokenServerResponse.ApiEndpoint,
		ApiKeyId:    tokenServerResponse.Id,
		ApiKey:      tokenServerResponse.Key,
	}

	app.credentialsCache.Put(credentials)

	return &credentials
}

//

func (app *Application) HandleProfile(w http.ResponseWriter, r *http.Request) {
	if credentials := app.authenticate(w, r); credentials != nil {
	}
}

//

type Tab struct {
	Title      string   `json:"title"`
	URLHistory []string `json:"urlHistory"`
	Icon       string   `json:"icon"`
}

type TabsPayload struct {
	Id         string `json:"id"`
	ClientName string `json:"clientName"`
	Tabs       []Tab  `json:"tabs"`
}

func (app *Application) login(w http.ResponseWriter, r *http.Request, credentials *Credentials) *sync.StorageClient {
	storageClient, err := sync.NewStorageClient(credentials.ApiEndpoint, credentials.ApiKeyId, credentials.ApiKey, credentials.KeyB)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return nil
	}

	if err := storageClient.Login(); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return nil
	}

	return storageClient
}

func (app *Application) HandleTabs(w http.ResponseWriter, r *http.Request) {
	if credentials := app.authenticate(w, r); credentials != nil {
		if storageClient := app.login(w, r, credentials); storageClient != nil {
			// Load the tabs

			records, err := storageClient.GetEncryptedRecords("tabs", nil, nil)
			if err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}

			// Parse the payload into Tab structs, then serialize that as a response

			tabsPayloads := []TabsPayload{}
			for _, record := range records {
				tabsPayload := TabsPayload{}
				if err = json.Unmarshal([]byte(record.Payload), &tabsPayload); err != nil {
					http.Error(w, err.Error(), http.StatusInternalServerError)
					return
				}
				tabsPayloads = append(tabsPayloads, tabsPayload)
			}

			encodedTabs, err := json.Marshal(tabsPayloads)
			if err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}

			w.Header().Set("Content-Type", "application/json")
			w.Write(encodedTabs)
		}
	}
}

//

type HistoryVisit struct {
	Date int `json:"date"`
	Type int `json:"type"`
}

type HistoryPayload struct {
	Id     string         `json:"id"`
	URL    string         `json:"histUri"`
	Title  string         `json:"title"`
	Visits []HistoryVisit `json:"visits"`
}

type HistoryPayloads []HistoryPayload

func (slice HistoryPayloads) Len() int {
	return len(slice)
}

func (slice HistoryPayloads) Less(i, j int) bool {
	return slice[i].Visits[0].Date < slice[j].Visits[0].Date
}

func (slice HistoryPayloads) Swap(i, j int) {
	slice[i], slice[j] = slice[j], slice[i]
}

func (app *Application) HandleHistoryRecent(w http.ResponseWriter, r *http.Request) {
	if credentials := app.authenticate(w, r); credentials != nil {
		if storageClient := app.login(w, r, credentials); storageClient != nil {
			// Load the most recent history
			records, err := storageClient.GetEncryptedRecords("history", nil, &sync.GetRecordsOptions{Limit: 100, Sort: "newest"})
			if err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}

			historyPayloads := HistoryPayloads{}
			for _, record := range records {
				historyPayload := HistoryPayload{}
				if err = json.Unmarshal([]byte(record.Payload), &historyPayload); err != nil {
					http.Error(w, err.Error(), http.StatusInternalServerError)
					return
				}
				historyPayloads = append(historyPayloads, historyPayload)
			}

			sort.Sort(sort.Reverse(historyPayloads))

			encodedHistory, err := json.Marshal(historyPayloads)
			if err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}

			w.Header().Set("Content-Type", "application/json")
			w.Write(encodedHistory)
		}
	}
}

//

func SetupRouter(r *mux.Router, config Config) (*Application, error) {
	app := &Application{
		config:           config,
		credentialsCache: NewCredentialsCache(CREDENTIALS_CACHE_TTL),
	}
	r.HandleFunc("/1.0/profile", app.HandleProfile)
	r.HandleFunc("/1.0/tabs", app.HandleTabs)
	r.HandleFunc("/1.0/history/recent", app.HandleHistoryRecent)
	return app, nil
}
