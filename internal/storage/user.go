package storage

type UserData struct {
	Y1, Y2, R1, R2, C []byte
}

type User interface {
	AddUser(user string, y1, y2 []byte) error
	UpdateUserRand(user string, r1, r2 []byte) error
	UpdateUserChallenge(user string, c []byte) error
	GetUser(user string) (*UserData, error)
	CheckUser(user string) (bool, error)
}
