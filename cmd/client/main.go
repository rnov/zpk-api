package main

import (
	"fmt"
	"github.com/gorilla/mux"
	"log"
	"net/http"
	"zkp-api/pkg/app/prover/handler"
	"zkp-api/pkg/app/prover/service"
	"zkp-api/pkg/config"
	"zkp-api/pkg/http/grpc"
)

func main() {
	proverCfg, err := config.LoadProverConfig("config/config.yaml")
	if err != nil {
		log.Fatalf("error loading prover config: %v", err)
	}

	conn, errC := grpc.InitClient(proverCfg.GRPCClient.Target)
	if errC != nil {
		log.Fatalf("unable to init client: %s", errC.Error())
	}

	pSrv := service.NewServerProver(conn)
	ah := handler.NewAuthHandler(pSrv)
	r := mux.NewRouter()
	r.HandleFunc("/register", ah.RegisterUserHandler).Methods("POST")
	r.HandleFunc("/login", ah.LoginUserHandler).Methods("POST")
	fmt.Println("starting server")
	// Fire up the server ":8080"
	log.Fatal(http.ListenAndServe(proverCfg.Port, r))
}
