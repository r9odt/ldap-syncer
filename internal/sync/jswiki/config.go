package jswiki

import (
	"context"
	"net/http"
	"time"

	"github.com/r9odt/go-logging"
	"github.com/r9odt/ldap-syncer/internal/client/ldap"
	"github.com/r9odt/ldap-syncer/internal/constant"
	"github.com/r9odt/ldap-syncer/internal/utils"
)

// Syncer represents a Gitlab syncer
type Syncer struct {
	IsDryRun bool
	Enabled  bool

	AllowDeleteUsers bool
	ApiURL           string
	Token            string
	UsersLdapGroup   string
	AdminLdapGroup   string
	LdapGroupPrefix  string
	UsersTZ          string

	SyncInterval time.Duration

	Logger logging.Logger
	Ctx    context.Context
	Ldap   ldap.Config

	client *http.Client

	jswikiUsers  map[int]*JsWikiUser
	jswikiGroups map[int]*JsWikiGroup

	ldapAllUsers     map[string]*User
	ldapExpiredUsers map[string]bool
}

// New return the Syncer object for Gitlab
func New(ctx context.Context, l ldap.Config, logger logging.Logger) (*Syncer, error) {
	var (
		c = &Syncer{
			IsDryRun:         utils.ParseBoolEnv(constant.IsDryRunEnv, false),
			Enabled:          utils.ParseBoolEnv(constant.IsJsWikiSyncEnabledEnv, true),
			Ctx:              ctx,
			Ldap:             l,
			AllowDeleteUsers: utils.ParseBoolEnv(constant.JsWikiAllowDeleteUsers, true),
			SyncInterval:     utils.ParseDurationEnv(constant.JsWikiSyncIntervalEnv, 30*time.Minute),
			ApiURL:           utils.ParseStringEnv(constant.JsWikiApiURLEnv, ""),
			Token:            utils.ParseStringEnv(constant.JsWikiTokenEnv, ""),
			UsersLdapGroup:   utils.ParseStringEnv(constant.JsWikiUsersLdapGroupEnv, "jswiki-users"),
			AdminLdapGroup:   utils.ParseStringEnv(constant.JsWikiAdminLdapGroupEnv, "jswiki-admins"),
			LdapGroupPrefix:  utils.ParseStringEnv(constant.JsWikiLdapGroupPrefixEnv, "jswiki-role-"),
			UsersTZ:          utils.ParseStringEnv(constant.JsWikiUsersTZEnv, "Asia/Krasnoyarsk"),
		}
	)

	c.client = &http.Client{
		Timeout: 2 * time.Second,
	}

	c.Logger = logger.Clone().String(constant.SyncerLogField, "jswiki")

	return c, c.validate()
}

func (s *Syncer) validate() error {
	var validateErrors uint8 = 0
	if !s.Enabled {
		return nil
	}
	if s.ApiURL == "" {
		s.Logger.Errorf(constant.RequiredFieldErrorMsg, constant.JsWikiApiURLEnv)
		validateErrors++
	}
	if s.Token == "" {
		s.Logger.Errorf(constant.RequiredFieldErrorMsg, constant.JsWikiTokenEnv)
		validateErrors++
	}
	if s.UsersLdapGroup == "" {
		s.Logger.Errorf(constant.RequiredFieldErrorMsg, constant.JsWikiUsersTZEnv)
		validateErrors++
	}
	if s.AdminLdapGroup == "" {
		s.Logger.Errorf(constant.RequiredFieldErrorMsg, constant.JsWikiAdminLdapGroupEnv)
		validateErrors++
	}

	if validateErrors > 0 {
		return constant.ErrValidate
	}
	return nil
}
