package service

import (
	"fmt"
	"google.golang.org/grpc"
	"math/big"
	"zkp-api/internal/zkp"
	"zkp-api/pkg/app/prover/client"
)

type Prover struct {
	// todo expose a http server for register and login
	Client client.Auth
}

func NewServerProver(conn *grpc.ClientConn) *Prover {
	return &Prover{
		Client: client.NewAuthClient(conn),
	}
}

type Auth interface {
	Register(user string, password big.Int) error
	AuthenticationChallenge(user string) (string, error)
}

func (p *Prover) Register(user string, password *big.Int) error {
	// from password and p.G, p.H using elliptic curve generate => y1 & y2
	y1, y2, err := zkp.GeneratePublicCommitments(password)
	if err != nil {
		// todo just log the error since there's no proto schema for errors
		return err
	}
	if err := p.Client.Register(user, y1, y2); err != nil {
		return err
	}

	return nil
}

// AuthenticationChallenge used for login
func (p *Prover) AuthenticationChallenge(user string, password *big.Int) (string, error) {
	// generate random r and produce 2 random points in the elliptic curve
	r1, r2, r, err := zkp.ProverCommitment()
	resp, err := p.Client.RequestAuthenticationChallenge(user, r1, r2)

	fmt.Println(resp.GetAuthId())
	fmt.Println(resp.GetC())
	if err != nil {
		return "", err
	}
	c := new(big.Int)
	c.SetBytes(resp.GetC())
	// solve the challenge c given by the verifier
	s, err := zkp.SolveChallenge(password, r, c)
	if err != nil {
		// todo just log the error since there's no proto schema for errors
	}
	authResp, err := p.Client.SendAuthentication(resp.GetAuthId(), s.Bytes())
	if err != nil {
		// todo just log the error since there's no proto schema for errors
		return "", err
	}

	return authResp.GetSessionId(), nil
}
