package client

import (
	"context"
	"google.golang.org/grpc"
	"time"
	pb "zkp-api/pkg/http/grpc/zkp"
)

// Auth defines the interface for the client that will interact with the prover service.
type Auth interface {
	Register(user string, y1, y2 []byte) error
	RequestAuthenticationChallenge(user string, r1, r2 []byte) (*pb.AuthenticationChallengeResponse, error)
	SendAuthentication(authId string, s []byte) (*pb.AuthenticationAnswerResponse, error)
}

// Client is a gRPC client that implements the Auth interface to communicate with the prover service.
type Client struct {
	client pb.AuthClient
}

// NewAuthClient creates a new Client with a gRPC connection to the prover service.
// It returns an Auth interface.
func NewAuthClient(conn *grpc.ClientConn) Auth {
	return &Client{
		client: pb.NewAuthClient(conn),
	}
}

// Register sends a registration request to the authentication service with the user's details and public commitments.
// It handles the context with a timeout for the gRPC call.
// Returns an error if the registration request fails.
func (a *Client) Register(user string, y1, y2 []byte) error {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	_, err := a.client.Register(ctx, &pb.RegisterRequest{User: user, Y1: y1, Y2: y2})
	return err
}

// RequestAuthenticationChallenge sends a request to the authentication service to initiate an authentication challenge for the user.
// It provides the user's details and random commitments as part of the request.
// Returns an AuthenticationChallengeResponse or an error if the request fails.
func (a *Client) RequestAuthenticationChallenge(user string, r1, r2 []byte) (*pb.AuthenticationChallengeResponse, error) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	return a.client.CreateAuthenticationChallenge(ctx, &pb.AuthenticationChallengeRequest{User: user, R1: r1, R2: r2})
}

// SendAuthentication sends the solution to the authentication challenge to the service.
// It includes the authentication ID and the solution as part of the request.
// Returns an AuthenticationAnswerResponse or an error if the request fails.
func (a *Client) SendAuthentication(authId string, s []byte) (*pb.AuthenticationAnswerResponse, error) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	return a.client.VerifyAuthentication(ctx, &pb.AuthenticationAnswerRequest{AuthId: authId, S: s})
}
