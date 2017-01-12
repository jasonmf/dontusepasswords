// package json provides Account storage in a simple, single JSON file. This
// module does no versioning or backups and is not suitable for non-trivial
// applications.
package json

import (
	"encoding/json"
	"os"
	"sync"

	"github.com/pkg/errors"

	"github.com/AgentZombie/dontusepasswords/account"
)

// Store holds the Account objects and can write them to disk.
type Store struct {
	path      string
	accounts  map[string]*account.Account
	writeLock sync.Mutex
}

// New creates a new Store object with the given file path. The create
// argument specifies whether or not a new store file should be created if it
// doesn't already exist.
func New(path string, create bool) (*Store, error) {
	accounts := map[string]*account.Account{}
	infh, err := os.Open(path)
	if err != nil {
		if os.IsNotExist(err) && create {
			return &Store{
				path:     path,
				accounts: accounts,
			}, nil
		} else {
			return nil, errors.Wrap(err, "reading account store")
		}
	}
	if err := json.NewDecoder(infh).Decode(&accounts); err != nil {
		return nil, errors.Wrap(err, "decoding account store")
	}
	return &Store{
		path:     path,
		accounts: accounts,
	}, nil
}

// Get retrieves an Account object by name.
func (s *Store) Get(name string) (*account.Account, error) {
	if a, ok := s.accounts[name]; ok {
		return a, nil
	}
	return nil, &account.NotFoundError{"not found"}
}

// Update updates the internal representation of an Account.
func (s *Store) Update(a *account.Account) error {
	s.accounts[a.Name] = a
	return nil
}

// Delete removes an Account from the store if it exists in the store.
func (s *Store) Delete(name string) error {
	delete(s.accounts, name)
	return nil
}

// Rename moves an Account to be stored under a new name, replacing an
// Account if one already exists with the new name. The Account object
// is modified to receive the new name.
func (s *Store) Rename(newname string, a *account.Account) error {
	old := a.Name
	s.accounts[newname] = a
	s.Delete(old)
	a.Name = newname
	return nil
}

// Flush writes all store data out to disk, overwriting existing data.
// Concurrent calls to Flush() are thread-safe but inefficient.
func (s *Store) Flush() error {
	s.writeLock.Lock()
	defer s.writeLock.Unlock()
	outfh, err := os.OpenFile(s.path, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		return errors.Wrap(err, "writing account store")
	}
	defer outfh.Close()
	if err := json.NewEncoder(outfh).Encode(&s.accounts); err != nil {
		return errors.Wrap(err, "encoding account store")
	}
	return nil
}
