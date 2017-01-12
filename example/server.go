package example

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"log"
	"net/http"

	"github.com/AgentZombie/dontusepasswords"
)

const (
	CookieName        = "DUPExample"
	SessionContextKey = "sessions"
)

type Server struct {
	accounts *dontusepasswords.Accounts
	sessions *Sessions
}

func NewServer(accounts *dontusepasswords.Accounts, sessions *Sessions) *Server {
	s := &Server{
		accounts: accounts,
		sessions: sessions,
	}
	http.HandleFunc("/", s.wrap(s.RootPage))
	http.HandleFunc("/login", s.Login)
	http.HandleFunc("/logout", s.wrap(s.Logout))
	http.HandleFunc("/adduser", s.wrap(s.AddUser))
	http.HandleFunc("/changepassword", s.wrap(s.ChangePassword))
	return s
}

func (s *Server) wrap(f func(http.ResponseWriter, *http.Request)) func(http.ResponseWriter, *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		cookie, err := r.Cookie(CookieName)
		if err != nil {
			http.Redirect(w, r, "/login", http.StatusFound)
			return
		}
		sess := s.sessions.Get(cookie.Value)
		if sess.Username == "" {
			http.Redirect(w, r, "/login", http.StatusFound)
			return
		}
		ctx := context.WithValue(r.Context(), SessionContextKey, sess)
		r = r.WithContext(ctx)
		f(w, r)
	}
}

func (s *Server) ListenAndServerHTTPS() error {
	// DON'T DO THIS. Use http.ListenAndServeTLS!
	return http.ListenAndServe(":8443", nil)
}

func (s *Server) Login(w http.ResponseWriter, r *http.Request) {
	if r.Method == "POST" {
		s.LoginAttempt(w, r)
		return
	}
	s.LoginPage(w, r)
}

func (s *Server) AddUser(w http.ResponseWriter, r *http.Request) {
	if r.Method == "POST" {
		s.AddUserAttempt(w, r)
		return
	}
	s.AddUserPage(w, r)
}

func (s *Server) ChangePassword(w http.ResponseWriter, r *http.Request) {
	if r.Method == "POST" {
		s.ChangePasswordAttempt(w, r)
		return
	}
	s.ChangePasswordPage(w, r)
}

func (s *Server) LoginPage(w http.ResponseWriter, r *http.Request) {
	w.Write([]byte(`
<html>
<head><title>Login</title></head>
<body>
<h1>Login</h1>
<form method="POST" action="/login">
<div>Username: <input type="text" name="username" size=32 /></div>
<div>Password: <input type="password" name="password" size=32 /></div>
<div><input type="submit" value="Login" /></div>
</form>
</body>
</html>
`))
}

func (s *Server) LoginAttempt(w http.ResponseWriter, r *http.Request) {
	username := r.FormValue("username")
	password := []byte(r.FormValue("password"))
	log.Print("login attempt for user ", username)
	res, err := s.accounts.Auth(username, password)
	if err != nil {
		log.Print("error: ", err)
	}
	if !res.Success {
		log.Print("login failed for user ", username)
		http.Redirect(w, r, "/login", http.StatusFound)
		return
	}
	log.Print("login succeeded for user ", username)
	sessID := make([]byte, 32)
	_, err = rand.Read(sessID)
	if err != nil {
		log.Print("error: reading random bytes: ", err)
	}
	sessStr := base64.StdEncoding.EncodeToString(sessID)
	sess := s.sessions.Get(sessStr)
	sess.Username = username
	http.SetCookie(w, &http.Cookie{
		Name:  CookieName,
		Value: sessStr,
	})
	http.Redirect(w, r, "/", http.StatusFound)
}

func (s *Server) AddUserPage(w http.ResponseWriter, r *http.Request) {
	w.Write([]byte(`
<html>
<head><title>Add User</title></head>
<body>
<h1>Add User</h1>
<form method="POST" action="/adduser"?
<div>Username: <input type="text" name="username" size=32 /></div>
<div>Password: <input type="password" name="password" size=32 /></div>
<div>Favorite Color: <input type="text" name="color" size=32 /></div>
<div><input type="submit" value="Login" /></div>
</form>
</body>
</html>
`))
}

func (s *Server) AddUserAttempt(w http.ResponseWriter, r *http.Request) {
	username := r.FormValue("username")
	password := []byte(r.FormValue("password"))
	color := r.FormValue("color")
	log.Print("attempting to add user ", username)
	a, err := s.accounts.New(username)
	if err != nil {
		log.Print("error: adding account: ", err)
		http.Redirect(w, r, "/adduser", http.StatusFound)
		return
	}
	a.AuxData = []byte(color)
	if err = s.accounts.NewChallenge(a, password); err != nil {
		log.Print("error: setting account challenge: ", err)
	}
	if err = s.accounts.Update(a); err != nil {
		log.Print("error: updating account: ", err)
	}
	log.Print("adding user succeeded")
	http.Redirect(w, r, "/", http.StatusFound)
}

func (s *Server) RootPage(w http.ResponseWriter, r *http.Request) {
	w.Write([]byte(`
<html>
<head><title>Example App</title></head>
<body>
<h1>Don't Use Passwords Example</h1>
<div><a href="/adduser">Add a User</a></div>
<div><a href="/changepassword">Change Your Password</a></div>
<div><a href="/logout">Logout</a></div>
</body>
</html>
`))
}

func (s *Server) ChangePasswordPage(w http.ResponseWriter, r *http.Request) {
	w.Write([]byte(`
<html>
<head><title>Change Password</title></head>
<body>
<h1>Change Your Password</h1>
<form method="POST" action="/changepassword">
<div>New Password: <input type="text" name="password" size=32 /></div>
<div><input type="submit" value="Change Password" /></div>
</form>
</body>
</html>
`))
}

func (s *Server) ChangePasswordAttempt(w http.ResponseWriter, r *http.Request) {
	sess := r.Context().Value(SessionContextKey).(*Session)
	log.Print("changing password for user ", sess.Username)
	password := []byte(r.FormValue("password"))
	a, err := s.accounts.Get(sess.Username)
	if err != nil {
		log.Print("error getting user: ", err)
		http.Redirect(w, r, "/changepassword", http.StatusFound)
		return
	}
	if err = s.accounts.NewChallenge(a, password); err != nil {
		log.Print("error calculating password: ", err)
	}
	if err = s.accounts.Update(a); err != nil {
		log.Print("error updating account: ", err)
	}
	http.Redirect(w, r, "/logout", http.StatusFound)
}

func (s *Server) Logout(w http.ResponseWriter, r *http.Request) {
	if sess, ok := r.Context().Value(SessionContextKey).(*Session); ok {
		s.sessions.Delete(sess.Id)
		http.SetCookie(w, &http.Cookie{})
	}
	http.Redirect(w, r, "/", http.StatusFound)
}
