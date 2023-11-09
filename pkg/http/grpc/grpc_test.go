package grpc

import (
	"context"
	"log"
	"testing"
	"time"
	pb "zkp-api/pkg/http/grpc/zkp"
)

// testServer is a mock gRPC server that implements the AuthServer interface
// for testing purposes. It provides dummy implementations for the Register,
// CreateAuthenticationChallenge, and VerifyAuthentication methods.
type testServer struct {
	// Embedding for forward compatibility.
	pb.UnimplementedAuthServer
}

// Register is a mock implementation that logs the received username and
// returns an empty RegisterResponse without any processing.
func (s *testServer) Register(ctx context.Context, in *pb.RegisterRequest) (*pb.RegisterResponse, error) {
	log.Printf("Received: %v", in.GetUser())
	return &pb.RegisterResponse{}, nil
}

// CreateAuthenticationChallenge is a mock implementation that returns a fixed
// AuthenticationChallengeResponse with a dummy AuthId and nil challenge.
func (s *testServer) CreateAuthenticationChallenge(ctx context.Context, req *pb.AuthenticationChallengeRequest) (*pb.AuthenticationChallengeResponse, error) {
	return &pb.AuthenticationChallengeResponse{AuthId: "auth123", C: nil}, nil
}

// VerifyAuthentication is a mock implementation that returns a fixed
// AuthenticationAnswerResponse with a dummy SessionId.
func (s *testServer) VerifyAuthentication(ctx context.Context, req *pb.AuthenticationAnswerRequest) (*pb.AuthenticationAnswerResponse, error) {
	return &pb.AuthenticationAnswerResponse{SessionId: "session123"}, nil
}

// TestConnection is a test function that sets up a mock gRPC server and client
// to test the Register functionality. It initializes the server and client,
// sends a RegisterRequest, and logs the response. It uses a table-driven approach
// to run subtests for different test cases.
func TestConnection(t *testing.T) {

	tests := []struct {
		name string
		req  *pb.RegisterRequest
	}{
		{
			name: "register request",
			req:  &pb.RegisterRequest{User: "Alice", Y1: nil, Y2: nil},
		},
	}

	ts := &testServer{}

	// note skip error check since it does not return once triggered therefore block mechanism do not work
	// just trigger a goroutine for simplicity
	go func() {
		_ = InitServer("tcp", ":50051", ts)
	}()

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
