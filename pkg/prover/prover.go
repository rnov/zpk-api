package prover

import "zkp-api/pkg/http/grpc"

type ServiceProver struct {
	//		todo http server to expose register and login for client
	AuthClient grpc.Client
}

func NewServerProver() *ServiceProver {
	return &ServiceProver{
		// todo
		AuthClient: &grpc.AuthClient{},
	}
}
