package virtual

import (
	"fmt"
	"sync"
	"zkp-api/pkg/storage"
)

// VerifierVirtualStorage is an in-memory storage for verifier user data.
// It uses a read-write mutex for concurrent access protection.
type VerifierVirtualStorage struct {
	// Embedding a pointer to a sync.RWMutex to protect concurrent access.
	*sync.RWMutex
	// Storage is a map that holds verifier user data indexed by username.
	Storage map[string]*storage.VerifierUserData
}

// NewVerifierStorage initializes and returns a new instance of VerifierVirtualStorage.
// It sets up the internal map to store verifier user data.
func NewVerifierStorage() *VerifierVirtualStorage {
	return &VerifierVirtualStorage{
		RWMutex: new(sync.RWMutex),
		Storage: make(map[string]*storage.VerifierUserData),
	}
}

// AddUser adds a new user to the storage with the provided username and public commitments (y1, y2).
// It locks the storage for writing, checks if the user already exists, and if not,
// adds the user to the storage. Returns an error if the user already exists.
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

// UpdateUserRand updates the random values (r1, r2) for a given user in the storage.
// It locks the storage for writing, checks if the user exists, and if so,
// updates the user's random values. Returns an error if the user does not exist.
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

// UpdateUserChallenge updates the challenge (c) for a given user in the storage.
// It locks the storage for writing, checks if the user exists, and if so,
// updates the user's challenge. Returns an error if the user does not exist.
func (u *VerifierVirtualStorage) UpdateUserChallenge(user string, c []byte) error {
	u.Lock()
	defer u.Unlock()
	if d := u.Storage[user]; d == nil {
		return fmt.Errorf("user does not exist")
	}
	u.Storage[user].C = c
	return nil
}

// GetUser retrieves the verifier user data for the given user from the storage.
// It locks the storage for reading, checks if the user exists, and if so,
// returns the user's data. Returns an error if the user does not exist.
func (u *VerifierVirtualStorage) GetUser(user string) (*storage.VerifierUserData, error) {
	u.Lock()
	defer u.Unlock()
	usr := u.Storage[user]
	if usr == nil {
		return nil, fmt.Errorf("user does not exist")
	}

	return usr, nil
}

// CheckUser checks if a user exists in the storage.
// It locks the storage for reading and returns true if the user exists, false otherwise.
// It does not return an error if the user does not exist, as the absence of a user is not
// considered an error condition in this context.
func (u *VerifierVirtualStorage) CheckUser(user string) (bool, error) {
	u.Lock()
	defer u.Unlock()
	if d := u.Storage[user]; d == nil {
		return false, nil
	}
	return true, nil
}
