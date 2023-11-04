package service

import (
	"fmt"
	"google.golang.org/grpc"
	"zkp-api/pkg/app/prover/client"
)

type Prover struct {
	// todo expose a http server for register and login
	Client client.Auth
	G      int64
	H      int64
}

func NewServerProver(conn *grpc.ClientConn, g, h int64) *Prover {

	return &Prover{
		Client: client.NewAuthClient(conn),
		G:      g,
		H:      h,
	}
}

type Auth interface {
	Register(user, password string) error
	AuthenticationChallenge(user string) (string, error)
}

func (p *Prover) Register(user, password string) error {
	// todo zkp calculate from password, p.G, p.H => y1 & y2
	var y1, y2 int64
	if err := p.Client.Register(user, y1, y2); err != nil {
		return err
	}

	return nil
}

func (p *Prover) AuthenticationChallenge(user string) (string, error) {
	// todo from zkp generate r1,r2
	var r1, r2 int64
	resp, err := p.Client.RequestAuthenticationChallenge(user, r1, r2)
	fmt.Println(resp.GetAuthId())
	fmt.Println(resp.GetC())
	if err != nil {
		return "", err
	}
	// todo from zkp solve the challenge from resp.GetC() => s
	var s int64
	authResp, err := p.Client.SendAuthentication(resp.GetAuthId(), s)
	if err != nil {
		return "", err
	}

	return authResp.GetSessionId(), nil
}

// auth from server side
//type Auth interface {
//	Register(user string, y1, y2 int64) error
//	CreateAuthenticationChallenge(user string, r1, r2 int64) error
//	VerifyAuthentication(authID string, s int64) error
//}
