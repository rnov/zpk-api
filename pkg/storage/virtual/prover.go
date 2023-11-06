package virtual

import (
	"fmt"
	"sync"
	"zkp-api/pkg/storage"
)

// ProverVirtualStorage -
type ProverVirtualStorage struct {
	*sync.RWMutex
	Storage map[string]*storage.ProverUserData
}

func NewProverStorage() *ProverVirtualStorage {
	return &ProverVirtualStorage{
		RWMutex: new(sync.RWMutex),
		Storage: make(map[string]*storage.ProverUserData),
	}
}

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

func (p *ProverVirtualStorage) GetUser(user string) ([]byte, error) {
	p.Lock()
	defer p.Unlock()
	if k, _ := p.Storage[user]; k == nil {
		return nil, fmt.Errorf("user %s does not exist", user)
	}
	return p.Storage[user].Password, nil
}
