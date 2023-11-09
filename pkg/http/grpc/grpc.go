package grpc

import (
	"google.golang.org/grpc"
	"log"
	"net"
	pb "zkp-api/pkg/http/grpc/zkp"
)

// InitServer initializes and starts a gRPC server on the specified network and address.
// It takes a network type (e.g., "tcp"), an address (e.g., ":50051"), and an implementation
// of the AuthServer interface to register with the gRPC server.
// It logs and exits the application if it fails to listen on the network address or if the server fails to serve.
func InitServer(network, address string, as pb.AuthServer) error {
	// "tcp", ":50051"
	lis, err := net.Listen(network, address)
	if err != nil {
		log.Fatalf("failed to listen: %v", err)
	}
	s := grpc.NewServer()
	pb.RegisterAuthServer(s, as)

	if err := s.Serve(lis); err != nil {
		log.Fatalf("failed to serve: %v", err)
	}

	return err
}

// InitClient creates and returns a gRPC client connection to the specified target address.
// The target is a string in the format "host:port" (e.g., "localhost:50051").
// It configures the client to connect without TLS and to block until the connection is established.
// It logs and exits the application if the connection fails.
func InitClient(target string) (*grpc.ClientConn, error) {
	// target: "localhost:50051"
	conn, err := grpc.Dial(target, grpc.WithInsecure(), grpc.WithBlock())
	if err != nil {
		log.Fatalf("did not connect: %v", err)
		return nil, err
	}

	return conn, err
}
