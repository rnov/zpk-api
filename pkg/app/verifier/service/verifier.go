package service

import (
	"fmt"
	"math/big"
	"zkp-api/internal/storage"
	"zkp-api/internal/zkp"
)

// AuthVerifier is composed by the entities that are needed to run the verifier server side
type AuthVerifier struct {
	UsrStorage storage.User // access to the store
	//AuthServer zkp.AuthServer
}

func NewServerVerifier() *AuthVerifier {
	return &AuthVerifier{
		UsrStorage: nil,
		//AuthServer: &AuthServer{},
	}
}

//type AuthServer struct {
//	zkp.UnimplementedAuthServer
//}

type Auth interface {
	Register(user string, y1, y2 []byte) error
	CreateAuthenticationChallenge(user string, r1, r2 []byte) ([]byte, error)
	VerifyAuthentication(authID string, s int64) (string, error)
}

func (v *AuthVerifier) Register(user string, y1, y2 []byte) error {
	// add public commitments of the user in storage
	if err := v.UsrStorage.AddUser(user, y1, y2); err != nil {
		// todo log and error, for this implementation in case already exist
		// todo just log the error since there's no proto schema for errors
		return err
	}
	return nil
}

func (v *AuthVerifier) CreateAuthenticationChallenge(user string, r1, r2 []byte) (*big.Int, error) {
	// todo check user exist
	if exist, err := v.UsrStorage.CheckUser(user); err != nil || !exist {
		// todo just log the error since there's no proto schema for errors
		return nil, err
	}

	// from received r1,r2 using zkp generate C challenge
	c := zkp.GenerateChallenge(r1, r2)
	fmt.Println("hit createAuthenticationChallenge")
	return c, nil
}

func (v *AuthVerifier) VerifyAuthentication(authID string, solution []byte) (string, error) {
	usr, err := v.UsrStorage.GetUser(authID)
	if err != nil {
		// todo just log the error since there's no proto schema for errors
		return "", err
	}

	// todo from received challenge response S, using zkp validate it and generate sessionID
	s := new(big.Int)
	s.SetBytes(solution)
	c := new(big.Int)
	c.SetBytes(usr.C)
	// verify prover solution
	if correct := zkp.Verify(usr.Y1, usr.Y2, usr.R1, usr.R2, s, c); !correct {
		// todo just log the error since there's no proto schema for errors
		return "", err
	}
	// todo generate a rnd string for auth
	return "", nil
}
