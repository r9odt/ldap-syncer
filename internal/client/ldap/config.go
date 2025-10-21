package ldap

import (
	"context"

	"github.com/go-ldap/ldap/v3"
	"github.com/r9odt/ldap-syncer/internal/constant"
	"github.com/r9odt/ldap-syncer/internal/logging"
	"github.com/r9odt/ldap-syncer/internal/utils"
)

type Config struct {
	LdapURL                   string
	LdapBindDN                string
	LdapBindPW                string
	LdapUsersBaseDN           string
	LdapGroupsBaseDN          string
	LdapUsernameAttr          string
	LdapGroupnameAttr         string
	LdapDisplayNameAttr       string
	LdapSSHKeyAttr            string
	LdapExpiredUsersDeltaDays uint64

	Logger logging.Logger
	Ctx    context.Context

	Connection *ldap.Conn
}

func New(ctx context.Context) (*Config, error) {
	var (
		c = &Config{
			Ctx:                       ctx,
			LdapURL:                   utils.ParseStringEnv(constant.LdapURLEnv, ""),
			LdapBindDN:                utils.ParseStringEnv(constant.LdapBindDNEnv, ""),
			LdapBindPW:                utils.ParseStringEnv(constant.LdapBindPWEnv, ""),
			LdapUsersBaseDN:           utils.ParseStringEnv(constant.LdapUsersBaseDNEnv, ""),
			LdapGroupsBaseDN:          utils.ParseStringEnv(constant.LdapGroupsBaseDNEnv, ""),
			LdapUsernameAttr:          utils.ParseStringEnv(constant.LdapUsernameAttrEnv, "uid"),
			LdapGroupnameAttr:         utils.ParseStringEnv(constant.LdapGroupnameAttrEnv, "cn"),
			LdapDisplayNameAttr:       utils.ParseStringEnv(constant.LdapDisplayNameAttrEnv, "displayName"),
			LdapSSHKeyAttr:            utils.ParseStringEnv(constant.LdapSSHKeyAttrEnv, "ipaSshPubKey"),
			LdapExpiredUsersDeltaDays: utils.ParseUInt64Env(constant.LdapExpiredUsersDeltaDaysEnv, 2),
		}
	)

	logger, err := logging.ConfigureLog(utils.ParseStringEnv(constant.LogFileEnv, "stdout"), utils.ParseStringEnv(constant.LogLevelEnv, "info"), "ldap", !utils.ParseBoolEnv(constant.LogJSONEnv, false))
	if err != nil {
		return nil, err
	}
	c.Logger = logger

	return c, c.validate()
}

func (c *Config) validate() error {
	var validateErrors uint8 = 0
	if c.LdapURL == "" {
		c.Logger.Errorf(constant.RequiredFieldErrorMsg, constant.LdapURLEnv)
		validateErrors++
	}
	if c.LdapBindDN == "" {
		c.Logger.Errorf(constant.RequiredFieldErrorMsg, constant.LdapBindDNEnv)
		validateErrors++
	}
	if c.LdapBindPW == "" {
		c.Logger.Errorf(constant.RequiredFieldErrorMsg, constant.LdapBindPWEnv)
		validateErrors++
	}
	if c.LdapUsersBaseDN == "" {
		c.Logger.Errorf(constant.RequiredFieldErrorMsg, constant.LdapUsersBaseDNEnv)
		validateErrors++
	}
	if c.LdapGroupsBaseDN == "" {
		c.Logger.Errorf(constant.RequiredFieldErrorMsg, constant.LdapGroupsBaseDNEnv)
		validateErrors++
	}
	if c.LdapUsernameAttr == "" {
		c.Logger.Errorf(constant.RequiredFieldErrorMsg, constant.LdapUsernameAttrEnv)
		validateErrors++
	}

	if validateErrors > 0 {
		return constant.ErrValidate
	}

	return nil
}
