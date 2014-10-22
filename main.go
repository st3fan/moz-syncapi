// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/

package main

import (
	"flag"
	"fmt"
	"github.com/gorilla/mux"
	"github.com/st3fan/moz-syncapi/syncapi"
	"log"
	"net/http"
)

const (
	DEFAULT_API_ROOT    = "/"
	DEFAULT_API_ADDRESS = "0.0.0.0"
	DEFAULT_API_PORT    = 8080
)

func main() {

	root := flag.String("root", DEFAULT_API_ROOT, "web root context")
	address := flag.String("address", DEFAULT_API_ADDRESS, "address to bind to")
	port := flag.Int("port", DEFAULT_API_PORT, "port to listen on")

	flag.Parse()

	config := syncapi.DefaultConfig()

	router := mux.NewRouter()
	_, err := syncapi.SetupRouter(router.PathPrefix(*root).Subrouter(), config)
	if err != nil {
		log.Fatal(err)
	}

	http.Handle("/", router)

	addr := fmt.Sprintf("%s:%d", *address, *port)
	log.Printf("Starting syncapi server on http://%s%s", addr, *root)
	err = http.ListenAndServe(addr, nil)
	if err != nil {
		log.Fatal(err)
	}
}
