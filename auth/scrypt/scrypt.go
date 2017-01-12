package scrypt

import (
	"bytes"
	"crypto/rand"

	"github.com/pkg/errors"
	"golang.org/x/crypto/scrypt"

	"github.com/AgentZombie/dontusepasswords/auth"
)

const (
	ScryptDefault = "SCRYPTDEFAULT" // Default-strength scrypt
)

func init() {
	auth.Register(ScryptDefault, &Scrypt{
		len:     32,
		saltLen: 32,
		n:       16384,
		r:       8,
		p:       1,
	})
}

type Scrypt struct {
	len     int
	saltLen int
	n       int
	r       int
	p       int
}

func (s Scrypt) Compute(v []byte) ([]byte, error) {
	salt := make([]byte, s.saltLen)
	n, err := rand.Read(salt)
	if n != s.saltLen {
		return nil, errors.New("wrong number of salt bytes read")
	}
	if err != nil {
		return nil, err
	}
	k, err := scrypt.Key(v, salt, s.n, s.r, s.p, s.len)
	if err != nil {
		return nil, err
	}
	return append(salt, k...), nil
}

func (s Scrypt) Verify(challenge, attempt []byte) bool {
	k, err := scrypt.Key(attempt, challenge[:s.saltLen], s.n, s.r, s.p, s.len)
	if err != nil {
		return false
	}
	return bytes.Equal(k, challenge[s.saltLen:])
}
