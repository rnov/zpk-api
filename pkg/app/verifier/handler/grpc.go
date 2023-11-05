package handler

import (
	"context"
	"log"
	"zkp-api/pkg/app/verifier/service"
	pb "zkp-api/pkg/http/grpc/zkp"
)

type Verifier struct {
	AuthVerify *service.AuthVerifier
	pb.UnimplementedAuthServer
}

func NewHandlerVerifier(av *service.AuthVerifier) *Verifier {
	return &Verifier{
		AuthVerify: av,
	}
}

func (p *Verifier) Register(ctx context.Context, in *pb.RegisterRequest) (*pb.RegisterResponse, error) {
	// fixme add logic here
	err := p.AuthVerify.Register(in.GetUser(), in.GetY1(), in.GetY2())
	if err != nil {
		return nil, err
	}
	log.Printf("Received: %v", in.GetUser())
	return &pb.RegisterResponse{}, nil
}

func (p *Verifier) CreateAuthenticationChallenge(ctx context.Context, req *pb.AuthenticationChallengeRequest) (*pb.AuthenticationChallengeResponse, error) {
	// fixme add logic here
	respC, err := p.AuthVerify.CreateAuthenticationChallenge(req.GetUser(), req.GetR1(), req.GetR2())
	if err != nil {
		return nil, err
	}
	//return &pb.AuthenticationChallengeResponse{AuthId: "auth123", C: 12345}, nil
	return &pb.AuthenticationChallengeResponse{AuthId: req.GetUser(), C: respC.Bytes()}, nil
}

func (p *Verifier) VerifyAuthentication(ctx context.Context, req *pb.AuthenticationAnswerRequest) (*pb.AuthenticationAnswerResponse, error) {
	// fixme add logic here
	sessionID, err := p.AuthVerify.VerifyAuthentication(req.GetAuthId(), req.GetS())
	if err != nil {
		return nil, err
	}
	return &pb.AuthenticationAnswerResponse{SessionId: sessionID}, nil
	//return &pb.AuthenticationAnswerResponse{SessionId: "session123"}, nil
}
