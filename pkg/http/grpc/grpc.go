package grpc

import (
	"google.golang.org/grpc"
	"log"
	"net"
	pb "zkp-api/pkg/http/grpc/zkp"
)

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

func InitClient(target string) (*grpc.ClientConn, error) {
	// target: "localhost:50051"
	conn, err := grpc.Dial(target, grpc.WithInsecure(), grpc.WithBlock())
	if err != nil {
		log.Fatalf("did not connect: %v", err)
		return nil, err
	}

	return conn, err
}
