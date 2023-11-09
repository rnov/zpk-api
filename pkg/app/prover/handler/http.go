package handler

import (
	"encoding/json"
	"math/big"
	"net/http"
	jr "zkp-api/pkg/app/prover/handler/request"
	"zkp-api/pkg/app/prover/service"
)

// AuthHandler is an HTTP handler that provides endpoints for user registration and login.
// Auth is a reference to the service that performs the actual authentication logic.
type AuthHandler struct {
	Auth service.Auth
}

// NewAuthHandler creates a new AuthHandler with a reference to an Auth service.
// It returns a pointer to the created AuthHandler.
func NewAuthHandler(auth service.Auth) *AuthHandler {
	return &AuthHandler{
		Auth: auth,
	}
}

// RegisterUserHandler handles the HTTP request for registering a new user.
// It decodes the request body into a RegisterReq struct, validates the password,
// and calls the Register method of the Auth (prover) service.
// Responds with an appropriate HTTP status code depending on the outcome of the operation.
func (a *AuthHandler) RegisterUserHandler(w http.ResponseWriter, r *http.Request) {
	req := &jr.RegisterReq{}
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(req); err != nil {
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	pwd, valid := new(big.Int).SetString(req.Password, 10)
	if !valid {
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	err := a.Auth.Register(req.UserName, pwd)
	if err != nil {
		// note this could be either a Status Bad Request or a InternalError, for
		// simplicity i've left out the custom errors from the design please refer to readme.
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
}

// LoginUserHandler handles the HTTP request for logging in a user.
// It decodes the request body into a LoginReq struct and calls the AuthenticationChallenge
// method of the Auth service to initiate the login process.
// If successful, it returns the challenge in the response body, otherwise it responds
// with an appropriate HTTP status code.
func (a *AuthHandler) LoginUserHandler(w http.ResponseWriter, r *http.Request) {
	req := &jr.LoginReq{}
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(req); err != nil {
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	resp, err := a.Auth.AuthenticationChallenge(req.UserName)
	if err != nil {
		// note this could be either a Status Bad Request or a InternalError, for
		// simplicity i've left out the custom errors from the design please refer to readme.
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	rBody := &jr.LoginResp{
		resp,
	}
	body, jsonErr := json.Marshal(rBody)
	if jsonErr != nil {
		// note should log error
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	_, _ = w.Write(body)
}
