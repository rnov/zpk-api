package grpc

import (
	"context"
	"google.golang.org/grpc"
	"log"
	"net"
	pb "zkp-api/pkg/http/grpc/zkp"
)

type Server interface {
	InitServer(network, address string) error
}

type AuthServer struct {
	// todo zkp struct instatiated here
	pb.UnimplementedAuthServer
}

// server

func (as *AuthServer) InitServer(network, address string) error {
	// "tcp", ":50051"
	lis, err := net.Listen(network, address)
	if err != nil {
		log.Fatalf("failed to listen: %v", err)
	}
	s := grpc.NewServer()
	//&AuthServer{}
	pb.RegisterAuthServer(s, as)

	go func() {
		if err := s.Serve(lis); err != nil {
			log.Fatalf("failed to serve: %v", err)
		}
	}()

	return err
}

// client

type Client interface {
	InitClient(target string) (pb.AuthClient, error)
}

type AuthClient struct{}

func (ac *AuthClient) InitClient(target string) (pb.AuthClient, error) {
	// target: "localhost:50051"
	conn, err := grpc.Dial(target, grpc.WithInsecure(), grpc.WithBlock())
	if err != nil {
		log.Fatalf("did not connect: %v", err)
		return nil, err
	}
	//defer conn.Close()
	//c := pb.NewAuthClient(conn)

	return pb.NewAuthClient(conn), err
}

// note move this elsewhere

func (s *AuthServer) Register(ctx context.Context, in *pb.RegisterRequest) (*pb.RegisterResponse, error) {
	// todo add logic here
	log.Printf("Received: %v", in.GetUser())
	return &pb.RegisterResponse{}, nil
}

func (s *AuthServer) CreateAuthenticationChallenge(ctx context.Context, req *pb.AuthenticationChallengeRequest) (*pb.AuthenticationChallengeResponse, error) {
	// todo add logic here
	return &pb.AuthenticationChallengeResponse{AuthId: "auth123", C: 12345}, nil
}

func (s *AuthServer) VerifyAuthentication(ctx context.Context, req *pb.AuthenticationAnswerRequest) (*pb.AuthenticationAnswerResponse, error) {
	// todo add logic here
	return &pb.AuthenticationAnswerResponse{SessionId: "session123"}, nil
}

// client

//conn, err := grpc.Dial("localhost:50051", grpc.WithInsecure(), grpc.WithBlock())
//	if err != nil {
//		log.Fatalf("did not connect: %v", err)
//	}
//	defer conn.Close()
//	c := pb.NewAuthClient(conn)
//
//	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
//	defer cancel()
//	r, err := c.Register(ctx, &pb.RegisterRequest{User: "Alice", Y1: 123, Y2: 456})
//	if err != nil {
//		log.Fatalf("could not register: %v", err)
//	}
//	log.Printf("Response: %v", r)
