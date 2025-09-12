package gitlab

import (
	"context"
	"time"

	"github.com/r9odt/ldap-syncer/internal/client/ldap"
	"github.com/r9odt/ldap-syncer/internal/constant"
	"github.com/r9odt/ldap-syncer/internal/logging"
	"github.com/r9odt/ldap-syncer/internal/utils"
	gitlab "gitlab.com/gitlab-org/api/client-go"
)

// Syncer represents a Gitlab syncer
type Syncer struct {
	IsDryRun bool

	ApiURL                      string
	Token                       string
	LdapProvider                string
	UsersLdapGroup              string
	AdminLdapGroup              string
	ProjectLimitLdapGroupPrefix string
	LdapGroupPrefix             string
	UserCanCreateTLGLdapGroup   string
	GroupDefaultAccessLevel     string
	UserDefaultProjectLimit     int
	UserDefaultCanCreateTLG     bool

	SyncInterval time.Duration

	Logger logging.Logger
	Ctx    context.Context
	Ldap   *ldap.Config

	client *gitlab.Client

	ldapAllUsers     map[string]*User
	ldapExpiredUsers map[string]bool
}

// New return the Syncer object for Gitlab
func New(ctx context.Context, l *ldap.Config) (*Syncer, error) {
	var (
		c *Syncer = &Syncer{
			IsDryRun:                    utils.ParseBoolEnv(constant.IsDryRunEnv, true),
			Ctx:                         ctx,
			Ldap:                        l,
			SyncInterval:                utils.ParseDurationEnv(constant.GitlabSyncIntervalEnv, 30*time.Minute),
			ApiURL:                      utils.ParseStringEnv(constant.GitlabApiURLEnv, ""),
			Token:                       utils.ParseStringEnv(constant.GitlabTokenEnv, ""),
			LdapProvider:                utils.ParseStringEnv(constant.GitlabLdapProviderEnv, "ldapmain"),
			UsersLdapGroup:              utils.ParseStringEnv(constant.GitlabUsersLdapGroupEnv, "gitlab-users"),
			AdminLdapGroup:              utils.ParseStringEnv(constant.GitlabAdminLdapGroupEnv, "gitlab-admins"),
			ProjectLimitLdapGroupPrefix: utils.ParseStringEnv(constant.GitlabProjectLimitLdapGroupPrefixEnv, "gitlab-prlimit-"),
			LdapGroupPrefix:             utils.ParseStringEnv(constant.GitlabLdapGroupPrefixEnv, "gitlab-group-"),
			UserCanCreateTLGLdapGroup:   utils.ParseStringEnv(constant.GitlabUserCanCreateTLGLdapGroupEnv, ""),
			GroupDefaultAccessLevel:     utils.ParseStringEnv(constant.GitlabGroupDefaultAccessLevelEnv, "reporter"),
			UserDefaultProjectLimit:     utils.ParseIntEnv(constant.GitlabUserDefaultProjectLimitEnv, 20),
			UserDefaultCanCreateTLG:     utils.ParseBoolEnv(constant.GitlabUserDefaultCanCreateTLGEnv, false),
		}
	)

	logger, err := logging.ConfigureLog(utils.ParseStringEnv(constant.LogFileEnv, "stdout"), utils.ParseStringEnv(constant.LogLevelEnv, "info"), "gitlab", !utils.ParseBoolEnv(constant.LogJSONEnv, false))

	if err != nil {
		return nil, err
	}
	c.Logger = logger
	c.ldapAllUsers = make(map[string]*User)
	c.ldapExpiredUsers = make(map[string]bool)

	return c, c.validate()
}

func (s *Syncer) validate() error {
	var validateErrors uint8 = 0
	if s.ApiURL == "" {
		s.Logger.Errorf(constant.RequiredFieldErrorMsg, constant.GitlabApiURLEnv)
		validateErrors++
	}
	if s.Token == "" {
		s.Logger.Errorf(constant.RequiredFieldErrorMsg, constant.GitlabTokenEnv)
		validateErrors++
	}
	if s.LdapProvider == "" {
		s.Logger.Errorf(constant.RequiredFieldErrorMsg, constant.GitlabLdapProviderEnv)
		validateErrors++
	}
	if s.UsersLdapGroup == "" {
		s.Logger.Errorf(constant.RequiredFieldErrorMsg, constant.GitlabUsersLdapGroupEnv)
		validateErrors++
	}
	if s.AdminLdapGroup == "" {
		s.Logger.Errorf(constant.RequiredFieldErrorMsg, constant.GitlabAdminLdapGroupEnv)
		validateErrors++
	}
	if s.GroupDefaultAccessLevel == "" {
		s.Logger.Errorf(constant.RequiredFieldErrorMsg, constant.GitlabGroupDefaultAccessLevelEnv)
		validateErrors++
	}
	if s.UserDefaultProjectLimit == 0 {
		s.Logger.Errorf(constant.MustPositiveErrorMsg, constant.GitlabUserDefaultProjectLimitEnv)
		validateErrors++
	}

	if validateErrors > 0 {
		return constant.ValidateError
	}
	return nil
}
