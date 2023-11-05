package client

import (
	"context"
	"google.golang.org/grpc"
	"time"
	pb "zkp-api/pkg/http/grpc/zkp"
)

type Auth interface {
	Register(user string, y1, y2 []byte) error
	RequestAuthenticationChallenge(user string, r1, r2 []byte) (*pb.AuthenticationChallengeResponse, error)
	SendAuthentication(authId string, s []byte) (*pb.AuthenticationAnswerResponse, error)
}

type Client struct {
	client pb.AuthClient
}

func NewAuthClient(conn *grpc.ClientConn) Auth {
	return &Client{
		client: pb.NewAuthClient(conn),
	}
}

func (a *Client) Register(user string, y1, y2 []byte) error {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	_, err := a.client.Register(ctx, &pb.RegisterRequest{User: user, Y1: y1, Y2: y2})
	return err
}

func (a *Client) RequestAuthenticationChallenge(user string, r1, r2 []byte) (*pb.AuthenticationChallengeResponse, error) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	return a.client.CreateAuthenticationChallenge(ctx, &pb.AuthenticationChallengeRequest{User: user, R1: r1, R2: r2})
}

func (a *Client) SendAuthentication(authId string, s []byte) (*pb.AuthenticationAnswerResponse, error) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	return a.client.VerifyAuthentication(ctx, &pb.AuthenticationAnswerRequest{AuthId: authId, S: s})
}
