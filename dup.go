// Package dontusepasswords provides password-based authentication in a way
// that minimizes the inherent insecurity of passwords. If any more secure
// alternative to passwords exists for your application, use that. If you must
// handle passwords, dontusepasswords is a decent choice.
package dontusepasswords

import (
	"time"

	"github.com/pkg/errors"

	"github.com/AgentZombie/dontusepasswords/account"
	"github.com/AgentZombie/dontusepasswords/auth"
)

// AuthResult provides details about the result of an authentication attempt.
type AuthResult struct {
	Account  *account.Account // The account object if authentication succeeded
	Success  bool             // Whether or not authentication succeeded
	Expired  bool             // Whether or not the challenge is expired
	Locked   bool             // Whether or not the account is administratively locked
	NotExist bool             // If no account with that name is found
}

// Accounts is the main point of interaction with dontusepasswords.
type Accounts struct {
	Store            account.Store // Storage for accounts
	PasswordLifetime time.Duration // How long before a password should be rotated
	AuthType         string        // Name of the auth scheme to use
}

// Get retrieves and account by name. To perform authentication use Auth() instead.
func (s Accounts) Get(name string) (*account.Account, error) {
	return s.Store.Get(name)
}

// Auth attempts to verify a user by a given attempt value which is usually
// a password. The returned AuthResult provides status details for the
// authentication attempt. The returned error is only used to indicate
// unexpected outcomes such as backend errors. An error may be returned on
// authentication success and authentication failure might return no error.
//
// If the account is not found or is locked, no challenge computation is
// performed. This could provide a means for an attacker to verify the
// existence of unlocked accounts by comparing the time it takes to process a
// request related to an existing, unlocked account and one that is not. It is
// up to the application developer to decide if such protection is warranted.
//
// If Expired is true in the AuthResult, the application should prompt the
// user to update their password.
//
// If authentication succeeds but the account challenge (hash) is stored
// using a different auth type than the one configured for the system (e.g.
// bcrypt vs scrypt), Auth will attempt to update the stored challenge using
// the configured auth mechanism. This may fail and return an error. In this
// case, the application should probably log the error for admin
// troubleshooting and let the user proceed.
func (s Accounts) Auth(name string, attempt []byte) (*AuthResult, error) {
	r := &AuthResult{}
	a, err := s.Get(name)
	if err != nil {
		if account.IsNotFound(err) {
			r.NotExist = true
			return r, nil
		}
		return r, errors.Wrap(err, "getting account")
	}
	r.Account = a
	if a.Locked {
		r.Locked = true
		return r, nil
	}
	r.Success, err = auth.Verify(a.AuthType, a.AuthData, attempt)
	if err != nil {
		return r, errors.Wrap(err, "verifying account")
	}
	if a.AuthType != s.AuthType {
		err = s.setChallenge(a, attempt)
		if err == nil {
			err = s.Update(a)
		}
	}
	return r, err
}

// New creates a new Account object, returning an error if an account with
// that name already exists. The account is not yet stored and there's the
// potential potential for a race condition.
func (s Accounts) New(name string) (*account.Account, error) {
	a, err := s.Store.Get(name)
	if a != nil {
		return nil, errors.Wrap(err, "account "+name+" already exists")
	}
	a = &account.Account{Name: name}
	return a, nil
}

// Updates the Account object in the store and calls the store's Flush() method.
func (s Accounts) Update(a *account.Account) error {
	err := s.Store.Update(a)
	if err != nil {
		return errors.Wrap(err, "updating account")
	}
	err = s.Store.Flush()
	if err != nil {
		return errors.Wrap(err, "flushing account update")
	}
	return nil
}

// Update the challenge value for the Account object and updates the expiration
// time. The underlying store is not updated.
//
// No restrictions are placed on passwords here. The application should not
// exclude any characters. It's reasonable for the application to impose a
// minimum length. The application should be very generous on maximum length
// (e.g. 256 characters).
func (s Accounts) NewChallenge(a *account.Account, v []byte) error {
	if err := s.setChallenge(a, v); err != nil {
		return errors.Wrap(err, "setting new challenge")
	}
	s.touchExpiration(a)
	return nil
}

func (s Accounts) setChallenge(a *account.Account, v []byte) error {
	v, err := auth.Compute(s.AuthType, v)
	if err != nil {
		return errors.Wrap(err, "computing new challenge for account")
	}
	a.AuthType = s.AuthType
	a.AuthData = v
	return nil
}

func (s Accounts) touchExpiration(a *account.Account) {
	a.Expires = time.Now().Add(s.PasswordLifetime)
}
