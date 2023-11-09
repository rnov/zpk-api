package main

import (
	"fmt"
	"log"
	"os"
	"zkp-api/pkg/app/verifier/handler"
	"zkp-api/pkg/app/verifier/service"
	"zkp-api/pkg/config"
	"zkp-api/pkg/http/grpc"
)

func main() {
	// Get the CONFIG_PATH environment variable, default to "config/config.yaml" if not set
	configPath := os.Getenv("CONFIG_PATH")
	if configPath == "" {
		configPath = "config/config.yaml"
	}

	// Load Verifier config
	verifierCfg, err := config.LoadVerifierConfig(configPath)
	if err != nil {
		log.Fatalf("error loading verifier config: %v", err)
	}

	// init verifier
	vSrv := service.NewServerVerifier()
	//HandlerVerifier
	hv := handler.NewHandlerVerifier(vSrv)

	fmt.Println("initializing grpc server")
	errS := grpc.InitServer(verifierCfg.Network, verifierCfg.Address, hv)
	if errS != nil {
		log.Fatalf("unable to init server: %s", errS.Error())
	}

}
