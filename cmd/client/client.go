package main

import (
	"fmt"
	"log"
	"time"
	"zkp-api/internal/config"
	"zkp-api/pkg/app/prover/service"
	"zkp-api/pkg/http/grpc"
)

func main() {
	// todo read client config from file
	cfg := config.Client{
		GRPCClient: config.GRPCClient{
			Target: "localhost:50051",
		},
	}

	conn, errC := grpc.InitClient(cfg.GRPCClient.Target)
	if errC != nil {
		log.Fatalf("unable to init client: %s", errC.Error())
	}

	pSrv := service.NewServerProver(conn)
	// note for test
	for {
		r, err := pSrv.Client.RequestAuthenticationChallenge("test", nil, nil)
		if err != nil {
			log.Fatalf("unable to connect server: %s", err.Error())
		} else {
			fmt.Println(r.GetC())
		}
		time.Sleep(2 * time.Second)
	}
	// todo run http client that exposes 2 endpoints

}
