package service

import (
	"fmt"
	"zkp-api/internal/storage"
)

// AuthVerifier is composed by the entities that are needed to run the verifier server side
type AuthVerifier struct {
	UsrStorage storage.User // access to the store
	//AuthServer zkp.AuthServer
	G int64
	H int64
}

func NewServerVerifier(g, h int64) *AuthVerifier {
	return &AuthVerifier{
		UsrStorage: nil,
		//AuthServer: &AuthServer{},
		G: g,
		H: h,
	}
}

//type AuthServer struct {
//	zkp.UnimplementedAuthServer
//}

type Auth interface {
	Register(user string, y1, y2 int64) error
	CreateAuthenticationChallenge(user string, r1, r2 int64) (int64, error)
	VerifyAuthentication(authID string, s int64) (string, error)
}

func (v *AuthVerifier) Register(user string, y1, y2 int64) error {
	// todo zkp calculate from p.G, p.H => y1 & y2 and validate with the input received

	return nil
}

func (v *AuthVerifier) CreateAuthenticationChallenge(user string, r1, r2 int64) (int64, error) {
	// todo from r1,r2 using zkp generate C challenge
	var c int64
	// note just for end-2-end test
	fmt.Println("hit createAuthenticationChallenge")
	c = 101
	return c, nil
}

func (v *AuthVerifier) VerifyAuthentication(authID string, s int64) (string, error) {
	// todo from received challenge response S, using zkp validate it and generate sessionID

	return "", nil
}
