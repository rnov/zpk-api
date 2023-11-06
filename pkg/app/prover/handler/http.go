package handler

import (
	"encoding/json"
	"math/big"
	"net/http"
	jr "zkp-api/pkg/app/prover/handler/request"
	"zkp-api/pkg/app/prover/service"
)

// AuthHandler - holds the service that manages auth operation
type AuthHandler struct {
	Auth service.Auth
}

// NewAuthHandler - auth handler constructor
func NewAuthHandler(auth service.Auth) *AuthHandler {
	return &AuthHandler{
		Auth: auth,
	}
}

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
