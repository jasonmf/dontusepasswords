package main

import (
	"log"
	"time"

	"github.com/AgentZombie/dontusepasswords"
	"github.com/AgentZombie/dontusepasswords/account/json"
	_ "github.com/AgentZombie/dontusepasswords/auth/bcrypt"
	_ "github.com/AgentZombie/dontusepasswords/auth/scrypt"
	"github.com/AgentZombie/dontusepasswords/example"
)

const (
	AccountsPath = "accounts.json"
	DefaultPass  = "insecuredefaultpassword"
)

func fatalIfError(err error) {
	if err != nil {
		log.Fatal(err)
	}
}

func main() {
	sessionDuration := time.Hour * 20
	sessions := example.NewSessions(sessionDuration)

	accountStore, err := json.New(AccountsPath, true)
	if err != nil {
		log.Fatal("error: ", err)
	}
	accounts := &dontusepasswords.Accounts{
		Store:            accountStore,
		PasswordLifetime: 24 * time.Hour * 365,
		AuthType:         "BCRYPTDEFAULT",
	}
	if _, err := accounts.Get("admin"); err != nil {
		admin, err := accounts.New("admin")
		fatalIfError(err)
		fatalIfError(accounts.NewChallenge(admin, []byte(DefaultPass)))
		fatalIfError(accounts.Update(admin))
		log.Printf("Admin account created with password %q", DefaultPass)
	}

	server := example.NewServer(accounts, sessions)
	log.Print("starting example server")
	fatalIfError(server.ListenAndServerHTTPS())
}
