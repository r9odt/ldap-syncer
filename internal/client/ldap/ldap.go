package ldap

import (
	"fmt"

	"github.com/go-ldap/ldap/v3"
	"github.com/r9odt/ldap-syncer/internal/constant"
)

// Connect is Ldap Connection without TLS
func (c *Config) Connect() error {
	l, err := ldap.DialURL(c.LdapURL)
	if err != nil {
		c.Logger.Errorf("Cannot connect to %s: %s", c.LdapURL, err.Error())
		return err
	}

	err = l.Bind(c.LdapBindDN, c.LdapBindPW)
	if err != nil {
		c.Logger.Errorf("Cannot bind ldap to %s: %s", c.LdapBindDN, err.Error())
		return err
	}
	c.Connection = l
	return nil
}

// Close ldap connection.
func (c *Config) Close() {
	if err := c.Connection.Close(); err != nil {
		c.Logger.Error("Closing connection error: %s", err.Error())
	}
}

// Check user in ldap
func (s *Config) IsLdapUserExist(username string) (error, bool) {
	var err error
	userSearchRequest := ldap.NewSearchRequest(
		s.LdapUsersBaseDN,
		1, 0, 0, 0, false,
		fmt.Sprintf(AttrFilter, ldap.EscapeFilter(s.LdapUsernameAttr), ldap.EscapeFilter(username)),
		// In-order request attributes
		[]string{
			s.LdapUsernameAttr,
		},
		nil,
	)

	sr, err := s.Connection.Search(userSearchRequest)
	if err != nil {
		s.Logger.
			String(constant.UserLogField, username).
			Error("Cannot search user:")
		return err, false
	}

	for _, en := range sr.Entries {
		for _, attr := range en.Attributes {
			switch attr.Name {
			case s.LdapUsernameAttr:
				return nil, true
			}
		}
	}
	return nil, false
}
