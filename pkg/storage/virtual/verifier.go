package virtual

import (
	"fmt"
	"sync"
	"zkp-api/pkg/storage"
)

// VerifierVirtualStorage - is a virtual memory storage for user Tokens that are used to authenticate them
type VerifierVirtualStorage struct {
	*sync.RWMutex
	Storage map[string]*storage.VerifierUserData
}

func NewVerifierStorage() *VerifierVirtualStorage {
	return &VerifierVirtualStorage{
		RWMutex: new(sync.RWMutex),
		Storage: make(map[string]*storage.VerifierUserData),
	}
}

func (u *VerifierVirtualStorage) AddUser(user string, y1, y2 []byte) error {
	u.Lock()
	defer u.Unlock()
	if d := u.Storage[user]; d != nil {
		return fmt.Errorf("user does exist")
	}
	ud := &storage.VerifierUserData{
		Y1: y1,
		Y2: y2,
	}
	u.Storage[user] = ud
	return nil
}

func (u *VerifierVirtualStorage) UpdateUserRand(user string, r1, r2 []byte) error {
	u.Lock()
	defer u.Unlock()
	if d := u.Storage[user]; d == nil {
		return fmt.Errorf("user does not exist")
	}
	u.Storage[user].R1 = r1
	u.Storage[user].R2 = r2
	return nil
}

func (u *VerifierVirtualStorage) UpdateUserChallenge(user string, c []byte) error {
	u.Lock()
	defer u.Unlock()
	if d := u.Storage[user]; d == nil {
		return fmt.Errorf("user does not exist")
	}
	u.Storage[user].C = c
	return nil
}

func (u *VerifierVirtualStorage) GetUser(user string) (*storage.VerifierUserData, error) {
	u.Lock()
	defer u.Unlock()
	usr := u.Storage[user]
	if usr == nil {
		return nil, fmt.Errorf("user does not exist")
	}

	return usr, nil
}

func (u *VerifierVirtualStorage) CheckUser(user string) (bool, error) {
	u.Lock()
	defer u.Unlock()
	if d := u.Storage[user]; d == nil {
		return false, nil
	}
	return true, nil
}
