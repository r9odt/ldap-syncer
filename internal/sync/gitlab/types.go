package gitlab

type User struct {
	dn           string
	isAdmin      bool
	displayName  string
	canCreateTLG bool
	projectLimit int
	sshKeys      []string
}

func (s *Syncer) newUser() *User {
	return &User{
		dn:           "",
		isAdmin:      false,
		displayName:  "",
		projectLimit: s.UserDefaultProjectLimit,
		canCreateTLG: s.UserDefaultCanCreateTLG,
		sshKeys:      make([]string, 0),
	}
}
