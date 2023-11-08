package handler

import (
	"context"
	"log"
	"zkp-api/pkg/app/verifier/service"
	pb "zkp-api/pkg/http/grpc/zkp"
)

// Verifier is a gRPC server handler that implements the AuthServer interface.
// It provides methods to register users and to handle authentication challenges and verification.
type Verifier struct {
	AuthVerify service.Auth
	pb.UnimplementedAuthServer
}

// NewHandlerVerifier creates a new Verifier handler with a reference to an Auth service.
// It returns a pointer to the created Verifier.
func NewHandlerVerifier(av service.Auth) *Verifier {
	return &Verifier{
		AuthVerify: av,
	}
}

// Register handles the gRPC call for registering a new user.
// It receives a RegisterRequest containing the user's details and public commitments,
// and it delegates the registration logic to the Auth service.
// Returns a RegisterResponse or an error if registration fails.
func (p *Verifier) Register(ctx context.Context, in *pb.RegisterRequest) (*pb.RegisterResponse, error) {
	err := p.AuthVerify.Register(in.GetUser(), in.GetY1(), in.GetY2())
	if err != nil {
		return nil, err
	}
	log.Printf("Received: %v", in.GetUser())
	return &pb.RegisterResponse{}, nil
}

// CreateAuthenticationChallenge handles the gRPC call to create a new authentication challenge.
// It receives an AuthenticationChallengeRequest with the user's details and random commitments,
// and it delegates the challenge creation to the Auth service.
// Returns an AuthenticationChallengeResponse containing the challenge or an error if the process fails.
func (p *Verifier) CreateAuthenticationChallenge(ctx context.Context, req *pb.AuthenticationChallengeRequest) (*pb.AuthenticationChallengeResponse, error) {
	respC, err := p.AuthVerify.CreateAuthenticationChallenge(req.GetUser(), req.GetR1(), req.GetR2())
	if err != nil {
		return nil, err
	}
	return &pb.AuthenticationChallengeResponse{AuthId: req.GetUser(), C: respC.Bytes()}, nil
}

// VerifyAuthentication handles the gRPC call to verify a user's authentication attempt.
// It receives an AuthenticationAnswerRequest with the authentication ID and the user's solution,
// and it delegates the verification to the Auth service.
// Returns an AuthenticationAnswerResponse with a session ID if verification is successful, or an error if it fails.
func (p *Verifier) VerifyAuthentication(ctx context.Context, req *pb.AuthenticationAnswerRequest) (*pb.AuthenticationAnswerResponse, error) {
	sessionID, err := p.AuthVerify.VerifyAuthentication(req.GetAuthId(), req.GetS())
	if err != nil {
		return nil, err
	}
	return &pb.AuthenticationAnswerResponse{SessionId: sessionID}, nil
}
