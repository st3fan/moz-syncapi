// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/

package main

import (
	"fmt"
	"github.com/gorilla/mux"
	"github.com/st3fan/moz-syncapi/syncapi"
	"log"
	"net/http"
)

const (
	DEFAULT_API_PREFIX         = "/"
	DEFAULT_API_LISTEN_ADDRESS = "0.0.0.0"
	DEFAULT_API_LISTEN_PORT    = 9090
)

func main() {

	config := syncapi.DefaultConfig()

	router := mux.NewRouter()
	_, err := syncapi.SetupRouter(router.PathPrefix(DEFAULT_API_PREFIX).Subrouter(), config)
	if err != nil {
		log.Fatal(err)
	}

	http.Handle("/", router)

	addr := fmt.Sprintf("%s:%d", DEFAULT_API_LISTEN_ADDRESS, DEFAULT_API_LISTEN_PORT)
	log.Printf("Starting syncapi server on http://%s%s", addr, DEFAULT_API_PREFIX)
	err = http.ListenAndServe(addr, nil)
	if err != nil {
		log.Fatal(err)
	}
}
