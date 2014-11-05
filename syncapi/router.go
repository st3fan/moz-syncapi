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
	Email       string
	Password    string
	KeyA        []byte
	KeyB        []byte
	ApiEndpoint string
	ApiKeyId    string
	ApiKey      string
}

func writeJSONResponse(w http.ResponseWriter, v interface{}) {
	b, err := json.Marshal(v)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.Write(b)
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
		requireBasicAuth(w, "Invalid Authorization Header (Failed to split username and password)")
		return nil
	}

	if app.credentialsCache != nil {
		credentials, ok := app.credentialsCache.Get(usernameAndPassword[0], usernameAndPassword[1])
		if ok {
			return &credentials
		}
	}

	// Do the FxA dance

	client, err := fxa.NewClient(usernameAndPassword[0], usernameAndPassword[1])
	if err != nil {
		log.Print("Could not create Fxa Client: ", err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return nil
	}

	if err := client.Login(); err != nil {
		http.Error(w, "Authorization failed: "+err.Error(), http.StatusUnauthorized)
		return nil
	}

	if err := client.FetchKeys(); err != nil {
		requireBasicAuth(w, "FetchKeys Failed: "+err.Error())
		return nil
	}

	key, err := generateRandomKey()
	if err != nil {
		log.Print("Could not generate DSA key: ", err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}

	cert, err := client.SignCertificate(key)
	if err != nil {
		requireBasicAuth(w, "SignCertificate Failed: "+err.Error())
		return nil
	}

	// Turn the certificate into an assertion

	issuedAt := time.Now().Add(-ASSERTION_OFFSET)
	expiresAt := issuedAt.Add(ASSERTION_DURATION)

	assertion, err := webtoken.CreateAssertion(*key, cert, "https://token.services.mozilla.com", "127.0.0.1", issuedAt, expiresAt)
	if err != nil {
		log.Print("CreateAssertion Failed: ", err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return nil
	}

	// Send the certificate to the token server

	tokenClient, _ := tokenclient.New()
	tokenServerResponse, err := tokenClient.ExchangeToken(assertion, "sync", "1.5", deriveClientStateFromKey(client.KeyB))
	if err != nil {
		log.Print("ExchangeToken Failed: ", err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return nil
	}

	//

	credentials := Credentials{
		Email:       usernameAndPassword[0],
		Password:    usernameAndPassword[1],
		KeyA:        client.KeyA,
		KeyB:        client.KeyB,
		ApiEndpoint: tokenServerResponse.ApiEndpoint,
		ApiKeyId:    tokenServerResponse.Id,
		ApiKey:      tokenServerResponse.Key,
	}

	if app.credentialsCache != nil {
		app.credentialsCache.Put(credentials, time.Duration(tokenServerResponse.Duration-15)*time.Second)
	}

	return &credentials
}

//

type ProfileResponse struct {
	Email  string `json:"email"`
	Name   string `json:"name"`
	Avatar string `json:"avatar"`
}

func (app *Application) HandleProfile(w http.ResponseWriter, r *http.Request) {
	if credentials := app.authenticate(w, r); credentials != nil {
		if storageClient := app.login(w, r, credentials); storageClient != nil {
			profileResponse := ProfileResponse{
				Email: credentials.Email,
			}

			encodedProfileResponse, err := json.Marshal(profileResponse)
			if err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}

			w.Header().Set("Content-Type", "application/json")
			w.Write(encodedProfileResponse)
		}
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

			writeJSONResponse(w, tabsPayloads)
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
	if len(slice[i].Visits) == 0 {
		return false
	}
	if len(slice[j].Visits) == 0 {
		return true
	}
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

			writeJSONResponse(w, historyPayloads)
		}
	}
}

//

type BookmarkPayload struct {
	Id         string   `json:"id"`
	Type       string   `json:"type"`
	ParentId   string   `json:"parentid"`
	ParentName string   `json:"parentName"`
	URL        string   `json:"bmkUri"`
	Tags       []string `json:"tags"`
	Title      string   `json:"title"`
	Children   []string `json:"children,omitempty"`
	Modified   float64  `json:"modified,omitempty"`
}

type BookmarkPayloads []BookmarkPayload

func (slice BookmarkPayloads) Len() int {
	return len(slice)
}

func (slice BookmarkPayloads) Less(i, j int) bool {
	return slice[i].Modified < slice[j].Modified
}

func (slice BookmarkPayloads) Swap(i, j int) {
	slice[i], slice[j] = slice[j], slice[i]
}

func (app *Application) HandleBookmarksRecent(w http.ResponseWriter, r *http.Request) {
	if credentials := app.authenticate(w, r); credentials != nil {
		if storageClient := app.login(w, r, credentials); storageClient != nil {
			// Load the most recent history

			records, err := storageClient.GetEncryptedRecords("bookmarks", nil, &sync.GetRecordsOptions{Limit: 100, Sort: "newest"})
			if err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}

			bookmarkPayloads := BookmarkPayloads{}
			for _, record := range records {
				bookmarkPayload := BookmarkPayload{}
				if err = json.Unmarshal([]byte(record.Payload), &bookmarkPayload); err != nil {
					http.Error(w, err.Error(), http.StatusInternalServerError)
					return
				}
				// There is no last visited time in bookmarks data so we use the time from the sync record
				bookmarkPayload.Modified = record.Modified
				// We are only interested in bookmarks, not folders
				if bookmarkPayload.Type == "bookmark" {
					bookmarkPayloads = append(bookmarkPayloads, bookmarkPayload)
				}
			}

			// sort.Sort(sort.Reverse(historyPayloads))

			writeJSONResponse(w, bookmarkPayloads)
		}
	}
}

type PostBookmarkRequest struct {
	Title string `json:"title"`
	URL   string `json:"url"`
}

func (app *Application) HandlePostBookmarks(w http.ResponseWriter, r *http.Request) {
	if credentials := app.authenticate(w, r); credentials != nil {
		if storageClient := app.login(w, r, credentials); storageClient != nil {
			decoder := json.NewDecoder(r.Body)
			var request PostBookmarkRequest
			if err := decoder.Decode(&request); err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}

			// First upload a new bookmark record

			//ts := sync.TimestampNow()

			// {"id":"QgGdEjN75N2J",
			//  "type":"bookmark",
			//  "title":"Replacing Dropbox with BitTorrent Sync | @jnoxon's thoughts",
			//  "parentName":"Unsorted Bookmarks",
			//  "bmkUri":"http://jeff.noxon.cc/2014/10/28/replacing-dropbox-with-bittorrent-sync/",
			//  "tags":[],
			//  "keyword":null,
			//  "description":"",
			//  "loadInSidebar":false,
			//  "parentid":"unfiled"}

			bookmarkPayload := BookmarkPayload{
				Id:       sync.RandomRecordId(),
				URL:      request.URL,
				Title:    request.Title,
				Type:     "bookmark",
				ParentId: "unfiled",
				Tags:     []string{},
			}

			encodedBookmarkPayload, err := json.Marshal(bookmarkPayload)
			if err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}

			bookmarkRecord := sync.Record{
				Id:        bookmarkPayload.Id,
				Payload:   string(encodedBookmarkPayload),
				SortIndex: 175,
			}

			// Then add the bookmark id to the unfiled record

			// {"id":"unfiled",
			//  "type": "folder",
			//  "parentName":"",
			//  "title":"Unsorted Bookmarks",
			//  "description":null,
			//  "children":["NdCgXw7rN3Fz","QgGdEjN75N2J"],
			//  "parentid":"places"}

			unfiledRecord, err := storageClient.GetEncryptedRecord("bookmarks", "unfiled", nil)
			if err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}

			unfiledPayload := BookmarkPayload{}
			if err = json.Unmarshal([]byte(unfiledRecord.Payload), &unfiledPayload); err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}

			unfiledPayload.Modified = 0
			unfiledPayload.Children = append(unfiledPayload.Children, bookmarkRecord.Id)

			encodedUnfiledPayload, err := json.Marshal(unfiledPayload)
			if err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}

			updatedUnfiledRecord := sync.Record{
				Id:        unfiledPayload.Id,
				Payload:   string(encodedUnfiledPayload),
				SortIndex: 1000000,
			}

			// Upload both records in the same batch

			records := []sync.Record{updatedUnfiledRecord, bookmarkRecord}

			if err := storageClient.PutEncryptedRecords("bookmarks", records, nil); err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
		}
	}
}

//

type ClientCommand struct {
	Command string   `json:"command"`
	Args    []string `json:"args"`
}

type ClientPayload struct {
	Id        string          `json:"id"`
	Name      string          `json:"name"`
	Type      string          `json:"type"`
	Version   string          `json:"version"`
	Protocols []string        `json:"protocols"`
	Commands  []ClientCommand `json:"commands,omitempty"`
}

func (app *Application) HandleGetClients(w http.ResponseWriter, r *http.Request) {
	if credentials := app.authenticate(w, r); credentials != nil {
		if storageClient := app.login(w, r, credentials); storageClient != nil {
			records, err := storageClient.GetEncryptedRecords("clients", nil, nil)
			if err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}

			clients := []ClientPayload{}
			for _, record := range records {
				log.Print(record.Payload)
				client := ClientPayload{}
				if err = json.Unmarshal([]byte(record.Payload), &client); err != nil {
					http.Error(w, err.Error(), http.StatusInternalServerError)
					return
				}
				clients = append(clients, client)
			}

			writeJSONResponse(w, clients)
		}
	}
}

//

type PostClientTabRequest struct {
	Title string `json:"title"`
	URL   string `json:"url"`
}

func (app *Application) HandlePostClientsTab(w http.ResponseWriter, r *http.Request) {
	if credentials := app.authenticate(w, r); credentials != nil {
		if storageClient := app.login(w, r, credentials); storageClient != nil {
			var request PostClientTabRequest
			if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}

			// Load the client record

			clientRecord, err := storageClient.GetEncryptedRecord("clients", mux.Vars(r)["clientId"], nil)
			if err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}

			client := ClientPayload{}
			if err = json.Unmarshal([]byte(clientRecord.Payload), &client); err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}

			// Add the url to push

			// TODO: This is not correct. What do we really need to do to the client record here?

			command := ClientCommand{
				Command: "displayURI",
				Args:    []string{request.URL, "doesnotexist", request.Title},
			}
			client.Commands = append(client.Commands, command)

			encodedClient, err := json.Marshal(client)
			if err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}

			clientRecord.Modified = sync.TimestampNow()
			clientRecord.Payload = string(encodedClient)

			// Send it back to the server

			if _, err := storageClient.PutEncryptedRecord("clients", clientRecord, nil); err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}

			writeJSONResponse(w, nil)
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
	r.HandleFunc("/1.0/bookmarks/recent", app.HandleBookmarksRecent)
	r.HandleFunc("/1.0/bookmarks", app.HandlePostBookmarks).Methods("POST")
	r.HandleFunc("/1.0/clients", app.HandleGetClients).Methods("GET")
	r.HandleFunc("/1.0/clients/{clientId}/tab", app.HandlePostClientsTab).Methods("POST")

	return app, nil
}
