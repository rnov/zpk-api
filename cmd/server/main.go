package main

import (
	"log"
	"zkp-api/pkg/app/verifier/handler"
	"zkp-api/pkg/app/verifier/service"
	"zkp-api/pkg/config"
	"zkp-api/pkg/http/grpc"
)

func main() {
	// Load Verifier config
	verifierCfg, err := config.LoadVerifierConfig("config/config.yaml")
	if err != nil {
		log.Fatalf("error loading verifier config: %v", err)
	}

	// init verifier
	vSrv := service.NewServerVerifier()
	//HandlerVerifier
	hv := handler.NewHandlerVerifier(vSrv)

	errS := grpc.InitServer(verifierCfg.Network, verifierCfg.Address, hv)
	if errS != nil {
		log.Fatalf("unable to init server: %s", errS.Error())
	}

}
