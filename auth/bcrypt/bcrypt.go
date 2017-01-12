// package bcrypt implements the bcrypt algorithm as an authentication method. Normally this package is imported only for side-effects:
//    import _ "dontusepasswords/auth/bcrypt"
package bcrypt

import (
	"golang.org/x/crypto/bcrypt"

	"github.com/AgentZombie/dontusepasswords/auth"
)

const (
	BcryptDefault = "BCRYPTDEFAULT" // Default-strength bcrypt
)

func init() {
	def := cost(bcrypt.DefaultCost)
	auth.Register(BcryptDefault, &def)
}

type cost int

func (c *cost) Verify(challenge, attempt []byte) bool {
	return bcrypt.CompareHashAndPassword(challenge, attempt) == nil
}

func (c *cost) Compute(v []byte) ([]byte, error) {
	return bcrypt.GenerateFromPassword(v, int(*c))
}
