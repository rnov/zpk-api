package storage

type VerifierUserData struct {
	Y1, Y2, R1, R2, C []byte
}

type VerifierStorage interface {
	AddUser(user string, y1, y2 []byte) error
	UpdateUserRand(user string, r1, r2 []byte) error
	UpdateUserChallenge(user string, c []byte) error
	GetUser(user string) (*VerifierUserData, error)
	CheckUser(user string) (bool, error)
}

type ProverUserData struct {
	Password []byte
}

type ProverStorage interface {
	AddUser(user string, password []byte) error
	GetUser(user string) ([]byte, error)
}
