package verifier

import (
	"zkp-api/internal/storage"
	"zkp-api/pkg/http/grpc"
)

// ServiceVerifier is composed by the entities that are needed to run the verifier server side
type ServiceVerifier struct {
	UsrStorage storage.User // access to the store
	AuthServer grpc.Server
}

// note not needed as of now cfg config.Server

func NewServerVerifier() *ServiceVerifier {
	return &ServiceVerifier{
		// todo
		UsrStorage: nil,
		AuthServer: &grpc.AuthServer{},
	}
}
