// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/

package syncapi

import (
	"encoding/base64"
	"github.com/gorilla/mux"
	//"github.com/st3fan/gofxa/fxa"
	"net/http"
	"strings"
)

type Application struct {
	config Config
}

type Credentials struct {
	Username string
	Password string
}

func (app *Application) authenticate(w http.ResponseWriter, r *http.Request) *Credentials {
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

	//client, err := fxa.Client()

	return &Credentials{
		Username: usernameAndPassword[0],
		Password: usernameAndPassword[1],
	}
}

func (app *Application) HandleProfile(w http.ResponseWriter, r *http.Request) {
	if credentials := app.authenticate(w, r); credentials != nil {

	}
}

func (app *Application) HandleTabs(w http.ResponseWriter, r *http.Request) {
	if credentials := app.authenticate(w, r); credentials != nil {

	}
}

func SetupRouter(r *mux.Router, config Config) (*Application, error) {
	app := &Application{config: config}
	r.HandleFunc("/1.0/profile", app.HandleProfile)
	r.HandleFunc("/1.0/tabs", app.HandleTabs)
	return app, nil
}
