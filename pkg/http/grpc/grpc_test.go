package grpc

import (
	"context"
	"log"
	"testing"
	"time"
	pb "zkp-api/pkg/http/grpc/zkp"
)

type testServer struct {
	pb.UnimplementedAuthServer
}

func (s *testServer) Register(ctx context.Context, in *pb.RegisterRequest) (*pb.RegisterResponse, error) {
	log.Printf("Received: %v", in.GetUser())
	return &pb.RegisterResponse{}, nil
}

func (s *testServer) CreateAuthenticationChallenge(ctx context.Context, req *pb.AuthenticationChallengeRequest) (*pb.AuthenticationChallengeResponse, error) {
	return &pb.AuthenticationChallengeResponse{AuthId: "auth123", C: 12345}, nil
}

func (s *testServer) VerifyAuthentication(ctx context.Context, req *pb.AuthenticationAnswerRequest) (*pb.AuthenticationAnswerResponse, error) {
	return &pb.AuthenticationAnswerResponse{SessionId: "session123"}, nil
}

func TestConnection(t *testing.T) {

	tests := []struct {
		name string
		req  *pb.RegisterRequest
	}{
		{
			name: "register request",
			req:  &pb.RegisterRequest{User: "Alice", Y1: 123, Y2: 456},
		},
	}

	ts := &testServer{}
	errS := InitServer("tcp", ":50051", ts)
	if errS != nil {
		t.Fatalf("unable to init server: %s", errS.Error())
	}

	conn, errC := InitClient("localhost:50051")
	if errC != nil {
		t.Fatalf("unable to init client: %s", errC.Error())
	}
	testConn := pb.NewAuthClient(conn)

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {

			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			r, err := testConn.Register(ctx, test.req)
			if err != nil {
				log.Fatalf("could not register: %v", err)
			}

			log.Printf("Response: %v", r)
		})
	}
}
