package main

import (
	"zkp-api/internal/config"
	"zkp-api/pkg/verifier"
)

func main() {
	// todo read server config from file
	cs := config.Server{}

	// init verifier
	v := verifier.NewServerVerifier()

	// start server listening on the given network and address
	if err := v.AuthServer.InitServer(cs.Network, cs.Address); err != nil {

	}

}
