package request

type RegisterReq struct {
	UserName string `json:"userName"`
	Password string `json:"password"` // registration password
}

type LoginReq struct {
	UserName string `json:"userName"`
}

type LoginResp struct {
	SessionID string `json:"sessionID"` // login password
}
