package service

import (
	"fmt"
	"google.golang.org/grpc"
	"log"
	"math/big"
	"zkp-api/pkg/app/prover/client"
	"zkp-api/pkg/storage"
	"zkp-api/pkg/storage/virtual"
	"zkp-api/pkg/zkp"
)

// Prover is a structure that holds the necessary components to facilitate the zero-knowledge proof
// based authentication process. It contains a storage to manage user data and a client to interact
// with the authentication service.
type Prover struct {
	UsrStorage storage.ProverStorage // access to the storage
	Client     client.Auth
}

// NewServerProver initializes a new Prover instance with a gRPC connection and a virtual storage.
// It returns a pointer to the created Prover.
func NewServerProver(conn *grpc.ClientConn) Auth {
	return &Prover{
		Client:     client.NewAuthClient(conn),
		UsrStorage: virtual.NewProverStorage(),
	}
}

// Auth is an interface that defines the methods for user registration and authentication.
type Auth interface {
	Register(user string, password *big.Int) error
	AuthenticationChallenge(user string) (string, error)
}

// Register takes a username and a password (as a big integer) and registers a new user in the system.
// It generates public commitments from the password and stores the user credentials.
// Returns an error if registration fails.
func (p *Prover) Register(user string, password *big.Int) error {
	// from password and p.G, p.H generate public commitments => y1 & y2
	y1, y2, err := zkp.GeneratePublicCommitments(password)
	if err != nil {
		// note just log the error since there's no proto schema for errors
		log.Printf(err.Error())
		return err
	}

	if err = p.Client.Register(user, y1, y2); err != nil {
		return err
	}

	if err = p.UsrStorage.AddUser(user, password.Bytes()); err != nil {
		// note just log the error since there's no proto schema for errors
		log.Printf(err.Error())
	}

	return nil
}

// AuthenticationChallenge initiates an authentication challenge for a user.
// It retrieves the user's password from storage, generates random commitments, and sends them to the authentication (verifier) service.
// Returns a session ID if the authentication is successful, or an error if the process fails.
func (p *Prover) AuthenticationChallenge(user string) (string, error) {
	pwdB, err := p.UsrStorage.GetUser(user)
	if err != nil {
		// note just log the error since there's no proto schema for errors
		log.Printf(err.Error())
		return "", err
	}
	password := new(big.Int).SetBytes(pwdB)
	// generate random r and produce 2 random commitments
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
		// note just log the error since there's no proto schema for errors
		log.Printf(err.Error())
	}
	authResp, err := p.Client.SendAuthentication(resp.GetAuthId(), s.Bytes())
	if err != nil {
		// note just log the error since there's no proto schema for errors
		log.Printf(err.Error())
		return "", err
	}

	return authResp.GetSessionId(), nil
}
