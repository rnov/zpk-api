package virtual

import (
	"fmt"
	"sync"
	"zkp-api/pkg/storage"
)

// ProverVirtualStorage is an in-memory storage for prover user data.
// It uses a read-write mutex for concurrent access protection.
type ProverVirtualStorage struct {
	// Embedding a pointer to a sync.RWMutex to protect concurrent access.
	*sync.RWMutex
	// Storage is a map that holds prover user data indexed by username.
	Storage map[string]*storage.ProverUserData
}

// NewProverStorage initializes and returns a new instance of ProverVirtualStorage.
// It sets up the internal map to store user data.
func NewProverStorage() *ProverVirtualStorage {
	return &ProverVirtualStorage{
		RWMutex: new(sync.RWMutex),
		Storage: make(map[string]*storage.ProverUserData),
	}
}

// AddUser adds a new user to the storage with the provided username and password.
// It locks the storage for writing, checks if the user already exists, and if not,
// adds the user to the storage. Returns an error if the user already exists.
func (p *ProverVirtualStorage) AddUser(user string, password []byte) error {
	p.Lock()
	defer p.Unlock()
	if k, _ := p.Storage[user]; k != nil {
		return fmt.Errorf("user %s already exist", user)
	}
	ud := &storage.ProverUserData{
		Password: password,
	}
	p.Storage[user] = ud
	return nil
}

// GetUser retrieves the password for the given user from the storage.
// It locks the storage for reading, checks if the user exists, and if so,
// returns the user's password. Returns an error if the user does not exist.
func (p *ProverVirtualStorage) GetUser(user string) ([]byte, error) {
	p.Lock()
	defer p.Unlock()
	if k, _ := p.Storage[user]; k == nil {
		return nil, fmt.Errorf("user %s does not exist", user)
	}
	return p.Storage[user].Password, nil
}
