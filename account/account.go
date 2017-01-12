// package account provides the structure for and account and some utility
// code related to the storage of Account objects.
package account

import (
	"time"
)

// Account represents an account within the application. Account names
// should be unique. The application should not directly modify AuthType,
// AuthData, or Expires.
type Account struct {
	Name     string    // The account name
	AuthType string    // The identifier for the mechanism by which the user's password is transformed and compared
	AuthData []byte    // The authentication token, managed by the authentication mechanism
	Locked   bool      // Whether or not the account is administratively locked
	Expires  time.Time // The date and time after which the AuthData is expired
	AuxData  []byte    // Arbitrary data the application stores with the Account
}

// Store collects the methods required of an underlying Account store.
type Store interface {
	Get(name string) (*Account, error)       // Retrieve an Account by name
	Update(a *Account) error                 // Update the internal representation of an Account
	Flush() error                            // Flush any changes to Account objects to storage
	Delete(name string) error                // Remove an Account from storage
	Rename(newname string, a *Account) error // Renames an account to the new name, replacing an existing Account and modifying the Account object to have the new name.
}

// NotFound can be implemented by errors in store packages to indicate that
// an account is not found.
type NotFound interface {
	IsNotFound() bool
}

// NotFoundError is a general purpose error that indicates that an Account
// is not found.
type NotFoundError struct {
	Str string
}

// String returns the string representation of the error.
func (nfe NotFoundError) String() string {
	return nfe.Str
}

// Error returns the string representation of the error.
func (nfe NotFoundError) Error() string {
	return nfe.Str
}

// IsNotFound indicates whether or not an Account was not found.
func (nfe NotFoundError) IsNotFound() bool {
	return true
}

// IsNotFound takens an arbitrary error and determines whether or not the
// error indicates that the Account was not found.
func IsNotFound(err error) bool {
	if nfe, ok := err.(NotFound); ok {
		return nfe.IsNotFound()
	}
	return false
}
