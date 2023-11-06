package service

import (
	"fmt"
	"google.golang.org/grpc"
	"math/big"
	"zkp-api/pkg/app/prover/client"
	"zkp-api/pkg/storage"
	"zkp-api/pkg/storage/virtual"
	"zkp-api/pkg/zkp"
)

type Prover struct {
	UsrStorage storage.ProverStorage // access to the storage
	Client     client.Auth
}

func NewServerProver(conn *grpc.ClientConn) *Prover {
	return &Prover{
		Client:     client.NewAuthClient(conn),
		UsrStorage: virtual.NewProverStorage(),
	}
}

type Auth interface {
	Register(user string, password *big.Int) error
	AuthenticationChallenge(user string) (string, error)
}

func (p *Prover) Register(user string, password *big.Int) error {
	// from password and p.G, p.H using elliptic curve generate => y1 & y2
	y1, y2, err := zkp.GeneratePublicCommitments(password)
	if err != nil {
		// todo just log the error since there's no proto schema for errors
		return err
	}

	if err = p.Client.Register(user, y1, y2); err != nil {
		return err
	}

	if err = p.UsrStorage.AddUser(user, password.Bytes()); err != nil {
		// todo just log the error since there's no proto schema for errors
	}

	return nil
}

// AuthenticationChallenge used for login
func (p *Prover) AuthenticationChallenge(user string) (string, error) {
	pwdB, err := p.UsrStorage.GetUser(user)
	if err != nil {
		// todo just log the error since there's no proto schema for errors
		return "", err
	}
	password := new(big.Int).SetBytes(pwdB)
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
