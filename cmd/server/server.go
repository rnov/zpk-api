package main

import (
	"log"
	"zkp-api/internal/config"
	"zkp-api/pkg/app/verifier/handler"
	"zkp-api/pkg/app/verifier/service"
	"zkp-api/pkg/http/grpc"
)

func main() {
	// todo read server config from file
	cfg := config.Server{
		GRPCServer: config.GRPCServer{
			Network: "tcp",
			Address: ":50051",
		},
	}

	// init verifier
	vSrv := service.NewServerVerifier()
	//HandlerVerifier
	hv := handler.NewHandlerVerifier(vSrv)

	errS := grpc.InitServer(cfg.Network, cfg.Address, hv)
	//errS := grpc.InitServer(cfg.Network, cfg.Network, vh.AuthVerify)
	if errS != nil {
		log.Fatalf("unable to init server: %s", errS.Error())
	}

}
