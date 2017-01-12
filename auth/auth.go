// package auth provides a common interface an registry for transforming
// passwords into a secure form.
package auth

import (
	"github.com/pkg/errors"
)

var (
	registry = map[string]ComputerVerifier{}
)

type InvalidType interface {
	IsInvalidType() bool
}

// IsInvalidType checks whether or not an error indicates an invalid auth
// type.
func IsInvalidType(err error) bool {
	if iit, ok := err.(InvalidType); ok {
		return iit.IsInvalidType()
	}
	return false
}

type invalidAuthType struct {
	AuthType string
}

func (i invalidAuthType) String() string {
	return "ivnalid auth type '" + i.AuthType + "'"
}

func (i invalidAuthType) Error() string {
	return i.String()
}

func (i *invalidAuthType) IsInvalidType() bool {
	return true
}

// Verifier objects can take a stored authentication challenge (e.g. a hash)
// and determine if the provided attempt value matches.
type Verifier interface {
	Verify(challenge, attempt []byte) bool
}

// Computer objects can take a user-supplied value and compute an
// authentication challenge
type Computer interface {
	Compute(v []byte) ([]byte, error)
}

// ComputerVerifier objects implement both Computer and Verifier
// functionality.
type ComputerVerifier interface {
	Computer
	Verifier
}

// Register is called by the init() functions of authentication modules to
// register those modules at run time. Supplied names must be unique.
func Register(name string, cv ComputerVerifier) error {
	if _, present := registry[name]; present {
		return errors.New("duplicate ComputerVerifier: " + name)
	}
	registry[name] = cv
	return nil
}

// Verify takes a precomputed authentication challenge and compares it to a
// supplied input to see if they match.
func Verify(authtype string, challenge, attempt []byte) (bool, error) {
	cv, ok := registry[authtype]
	if !ok {
		return false, &invalidAuthType{authtype}
	}
	return cv.Verify(challenge, attempt), nil
}

// Compute takes a supplied value and transforms it into an authentication
// challenge using the supplied authtype.
func Compute(authtype string, v []byte) ([]byte, error) {
	cv, ok := registry[authtype]
	if !ok {
		return nil, &invalidAuthType{authtype}
	}
	return cv.Compute(v)
}
