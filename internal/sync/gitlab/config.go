package gitlab

import (
	"context"
	"fmt"
	"time"

	"github.com/r9odt/go-logging"
	"github.com/r9odt/ldap-syncer/internal/client/ldap"
	"github.com/r9odt/ldap-syncer/internal/constant"
	"github.com/r9odt/ldap-syncer/internal/utils"
	gitlab "gitlab.com/gitlab-org/api/client-go"
)

type registry struct {
	RegistryCleanupPolicyEnabled bool
	RegsitryCadence              string
	RegsitryKeepTagsRegex        string
	RegsitryKeepMostRecent       int64
	RegsitryRemoveTagsRegex      string
	RegsitryRemoveOlderThan      string

	regsitryCleanupPolicy gitlab.ContainerExpirationPolicy
}

// Syncer represents a Gitlab syncer
type Syncer struct {
	IsDryRun bool
	Enabled  bool

	AllowDeleteUsers            bool
	ApiURL                      string
	Token                       string
	LdapProvider                string
	UsersLdapGroup              string
	AdminLdapGroup              string
	ProjectLimitLdapGroupPrefix string
	LdapGroupPrefix             string
	UserCanCreateTLGLdapGroup   string
	GroupDefaultAccessLevel     string
	UserDefaultProjectLimit     int64
	UserDefaultCanCreateTLG     bool

	registry

	SyncInterval                time.Duration
	ProjectSettingsSyncInterval time.Duration
	GroupsSyncInterval          time.Duration

	Logger logging.Logger
	Ctx    context.Context
	Ldap   ldap.Config

	client *gitlab.Client

	ldapAllUsers     map[string]*User
	ldapExpiredUsers map[string]bool
}

// New return the Syncer object for Gitlab
func New(ctx context.Context, l ldap.Config, logger logging.Logger) (*Syncer, error) {
	var (
		c = &Syncer{
			IsDryRun:                    utils.ParseBoolEnv(constant.IsDryRunEnv, false),
			Enabled:                     utils.ParseBoolEnv(constant.IsGilabSyncEnabledEnv, true),
			Ctx:                         ctx,
			Ldap:                        l,
			AllowDeleteUsers:            utils.ParseBoolEnv(constant.GitlabAllowDeleteUsersEnv, true),
			SyncInterval:                utils.ParseDurationEnv(constant.GitlabSyncIntervalEnv, 30*time.Minute),
			ProjectSettingsSyncInterval: utils.ParseDurationEnv(constant.GitlabProjectSettingsSyncIntervalEnv, 24*time.Hour),
			GroupsSyncInterval:          utils.ParseDurationEnv(constant.GitlabGroupsSyncIntervalEnv, 1*time.Hour),
			ApiURL:                      utils.ParseStringEnv(constant.GitlabApiURLEnv, ""),
			Token:                       utils.ParseStringEnv(constant.GitlabTokenEnv, ""),
			LdapProvider:                utils.ParseStringEnv(constant.GitlabLdapProviderEnv, "ldapmain"),
			UsersLdapGroup:              utils.ParseStringEnv(constant.GitlabUsersLdapGroupEnv, "gitlab-users"),
			AdminLdapGroup:              utils.ParseStringEnv(constant.GitlabAdminLdapGroupEnv, "gitlab-admins"),
			ProjectLimitLdapGroupPrefix: utils.ParseStringEnv(constant.GitlabProjectLimitLdapGroupPrefixEnv, "gitlab-prlimit-"),
			LdapGroupPrefix:             utils.ParseStringEnv(constant.GitlabLdapGroupPrefixEnv, "gitlab-group-"),
			UserCanCreateTLGLdapGroup:   utils.ParseStringEnv(constant.GitlabUserCanCreateTLGLdapGroupEnv, ""),
			GroupDefaultAccessLevel:     utils.ParseStringEnv(constant.GitlabGroupDefaultAccessLevelEnv, "reporter"),
			UserDefaultProjectLimit:     utils.ParseInt64Env(constant.GitlabUserDefaultProjectLimitEnv, 20),
			UserDefaultCanCreateTLG:     utils.ParseBoolEnv(constant.GitlabUserDefaultCanCreateTLGEnv, false),
			registry: registry{
				RegistryCleanupPolicyEnabled: utils.ParseBoolEnv(constant.GitlabRegistryCleanupPolicyEnabledEnv, false),
				RegsitryCadence:              utils.ParseStringEnv(constant.GitlabRegistryCadenceEnv, "1d"),
				RegsitryKeepTagsRegex:        utils.ParseStringEnv(constant.GitlabRegistryKeepRegexEnv, "(?:v??[\\d]+.[\\d]+.[\\d]+(?:-rc[\\d]+)??)|(\\d{4})"),
				RegsitryKeepMostRecent:       utils.ParseInt64Env(constant.GitlabRegistryKeepRecentEnv, 10),
				RegsitryRemoveTagsRegex:      utils.ParseStringEnv(constant.GitlabRegistryRemoveRegexEnv, ".*"),
				RegsitryRemoveOlderThan:      utils.ParseStringEnv(constant.GitlabRegistryRemoveOlderEnv, "14d"),
			},
		}
	)

	registryPolicyNameRegexKeep := fmt.Sprintf("^((%s)|(%s))$", SyncRegistryPolicyControlString, c.RegsitryKeepTagsRegex)
	c.regsitryCleanupPolicy = gitlab.ContainerExpirationPolicy{
		Enabled:         c.RegistryCleanupPolicyEnabled,
		Cadence:         c.RegsitryCadence,
		KeepN:           c.RegsitryKeepMostRecent,
		OlderThan:       c.RegsitryRemoveOlderThan,
		NameRegexDelete: c.RegsitryRemoveTagsRegex,
		NameRegexKeep:   registryPolicyNameRegexKeep,
	}
	c.Logger = logger.Clone().String(constant.SyncerLogField, "gitlab")

	return c, c.validate()
}

func (s *Syncer) validate() error {
	var validateErrors uint8 = 0
	if !s.Enabled {
		return nil
	}
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
		return constant.ErrValidate
	}
	return nil
}
