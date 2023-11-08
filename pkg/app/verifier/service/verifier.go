package service

import (
	"fmt"
	"log"
	"math/big"
	"zkp-api/pkg/storage"
	"zkp-api/pkg/storage/virtual"
	"zkp-api/pkg/zkp"
)

// AuthVerifier is a structure that holds the necessary components to facilitate the zero-knowledge proof
// based verification process. It contains a storage to manage user data.
type AuthVerifier struct {
	UsrStorage storage.VerifierStorage // access to the store
}

// NewServerVerifier initializes a new AuthVerifier instance with a virtual storage.
// It returns a pointer to the created AuthVerifier.
func NewServerVerifier() Auth {
	return &AuthVerifier{
		UsrStorage: virtual.NewVerifierStorage(),
	}
}

// Auth is an interface that defines the methods for user registration and authentication verification.
type Auth interface {
	Register(user string, y1, y2 []byte) error
	CreateAuthenticationChallenge(user string, r1, r2 []byte) (*big.Int, error)
	VerifyAuthentication(authID string, solution []byte) (string, error)
}

// Register takes a username and public commitments (y1, y2) and registers a new user in the system.
// It stores the user's public commitments in the storage.
// Returns an error if registration fails.
func (v *AuthVerifier) Register(user string, y1, y2 []byte) error {
	// add public commitments of the user in storage
	if err := v.UsrStorage.AddUser(user, y1, y2); err != nil {
		// note just log the error since there's no proto schema for errors
		log.Printf(err.Error())
		return err
	}
	return nil
}

// CreateAuthenticationChallenge generates a challenge for the user based on random commitments (r1, r2).
// It checks if the user exists and updates the user's challenge and random values in the storage.
// Returns the generated challenge as a big integer or an error if the process fails.
func (v *AuthVerifier) CreateAuthenticationChallenge(user string, r1, r2 []byte) (*big.Int, error) {
	if exist, err := v.UsrStorage.CheckUser(user); err != nil || !exist {
		if err == nil {
			err = fmt.Errorf("user '%s' does not exist", user)
		}
		log.Printf(err.Error())
		return nil, err
	}

	// from received r1,r2 using zkp generate C challenge
	c := zkp.GenerateChallenge(r1, r2)
	if c == nil {
		err := fmt.Errorf("error generating challenge")
		log.Printf(err.Error())
	}

	if err := v.UsrStorage.UpdateUserChallenge(user, c.Bytes()); err != nil {
		// note just log the error since there's no proto schema for errors
		log.Printf(err.Error())
		return nil, err
	}
	if err := v.UsrStorage.UpdateUserRand(user, r1, r2); err != nil {
		// note just log the error since there's no proto schema for errors
		log.Printf(err.Error())
		return nil, err
	}

	return c, nil
}

// VerifyAuthentication takes an authentication ID and a solution (as a byte slice) and verifies the solution against the stored challenge.
// It retrieves the user's data using the authentication ID, verifies the solution, and returns an authentication result.
// Returns a success message or an error if the verification fails.
func (v *AuthVerifier) VerifyAuthentication(authID string, solution []byte) (string, error) {
	usr, err := v.UsrStorage.GetUser(authID)
	if err != nil {
		// not just log the error since there's no proto schema for errors
		log.Printf(err.Error())
		return "", err
	}

	s := new(big.Int)
	s.SetBytes(solution)
	c := new(big.Int)
	c.SetBytes(usr.C)
	// verify prover solution
	if correct := zkp.Verify(usr.Y1, usr.Y2, usr.R1, usr.R2, s, c); !correct {
		// note just log the error since there's no proto schema for errors
		err = fmt.Errorf("error verifiying the solution")
		log.Printf(err.Error())
		return "", err
	}
	// todo generate a rnd string for auth
	return "successfully logged", nil
}
