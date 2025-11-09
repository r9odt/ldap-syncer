package constant

import "fmt"

const (
	// IsDryRunEnv environment variable name
	IsDryRunEnv string = "SYNC_DRY_RUN"
	// LogLevelEnv environment variable name
	LogLevelEnv string = "LOG_LEVEL"
	// LogJSONEnv environment variable name
	LogJSONEnv string = "LOG_JSON_FORMAT"
	// LogFileEnv environment variable name
	LogFileEnv string = "LOG_FILE"

	// IsGilabSyncEnabledEnv environment variable name
	IsGilabSyncEnabledEnv string = "SYNC_GITLAB_ENABLED"
	// IsJsWikiSyncEnabledEnv environment variable name
	IsJsWikiSyncEnabledEnv string = "SYNC_JSWIKI_ENABLED"

	// LdapURLEnv environment variable name
	LdapURLEnv string = "LDAP_URL"
	// LdapBindDNEnv environment variable name
	LdapBindDNEnv string = "LDAP_BIND_DN"
	// LdapBindPWEnv environment variable name
	LdapBindPWEnv string = "LDAP_BIND_PASSWORD"
	// LdapUsersBaseDNEnv environment variable name
	LdapUsersBaseDNEnv string = "LDAP_USERS_BASE_DN"
	// LdapGroupsBaseDNEnv environment variable name
	LdapGroupsBaseDNEnv string = "LDAP_GROUP_BASE_DN"
	// LdapUsernameAttrEnv environment variable name
	LdapUsernameAttrEnv string = "LDAP_USERNAME_ATTRIBUTE"
	// LdapGroupnameAttrEnv environment variable name
	LdapGroupnameAttrEnv string = "LDAP_GROUPNAME_ATTRIBUTE"
	// LdapDisplayNameAttrEnv environment variable name
	LdapDisplayNameAttrEnv string = "LDAP_DISPLAY_NAME_ATTRIBUTE"
	// LdapSSHKeyAttrEnv environment variable name
	LdapSSHKeyAttrEnv string = "LDAP_SSH_KEY_ATTRIBUTE"
	// LdapExpiredUsersDeltaDaysEnv environment variable name
	LdapExpiredUsersDeltaDaysEnv string = "LDAP_EXPIRED_USERS_DELTA_DAYS"

	// GitlabApiURLEnv environment variable name
	GitlabApiURLEnv string = "GITLAB_API_URL"
	// GitlabTokenEnv environment variable name
	GitlabTokenEnv string = "GITLAB_TOKEN"
	// GitlabLdapProviderEnv environment variable name
	GitlabLdapProviderEnv string = "GITLAB_LDAP_PROVIDER"
	// GitlabSyncIntervalEnv environment variable name
	GitlabSyncIntervalEnv string = "GITLAB_SYNC_INTERVAL"
	// GitlabUsersLdapGroupEnv environment variable name
	GitlabUsersLdapGroupEnv string = "LDAP_GITLAB_USERS_GROUP"
	// GitlabAdminLdapGroupEnv environment variable name
	GitlabAdminLdapGroupEnv string = "LDAP_GITLAB_ADMIN_GROUP"
	// LdapGroupPrefixEnv environment variable name
	GitlabLdapGroupPrefixEnv string = "LDAP_GITLAB_GROUP_PREFIX"
	// ProjectLimitLdapGroupPrefixEnv environment variable name
	GitlabProjectLimitLdapGroupPrefixEnv string = "LDAP_GITLAB_PROJECT_LIMIT_GROUP_PREFIX"
	// GitlabGroupDefaultAccessLevelEnv environment variable name
	GitlabGroupDefaultAccessLevelEnv string = "GITLAB_GROUP_DEFAULT_ACCESS_LEVEL"
	// GitlabUserDefaultProjectLimitEnv environment variable name
	GitlabUserDefaultProjectLimitEnv string = "GITLAB_USER_DEFAULT_PROJECT_LIMIT"
	// GitlabUserDefaultCanCreateTLGEnv environment variable name
	GitlabUserDefaultCanCreateTLGEnv string = "GITLAB_USER_DEFAULT_CAN_CREATE_TLG"
	// GitlabUserCanCreateTLGLdapGroupEnv environment variable name
	GitlabUserCanCreateTLGLdapGroupEnv string = "LDAP_GITLAB_USER_CAN_CREATE_TLG_GROUP"

	// JsWikiApiURLEnv environment variable name
	JsWikiApiURLEnv string = "JSWIKI_API_URL"
	// JsWikiTokenEnv environment variable name
	JsWikiTokenEnv string = "JSWIKI_TOKEN"
	// JsWikiUsersTZEnv environment variable name
	JsWikiUsersTZEnv string = "JSWIKI_USERS_TZ"
	// JsWikiSyncIntervalEnv environment variable name
	JsWikiSyncIntervalEnv string = "JSWIKI_SYNC_INTERVAL"
	// JsWikiUsersLdapGroupEnv environment variable name
	JsWikiUsersLdapGroupEnv string = "LDAP_JSWIKI_USERS_GROUP"
	// JsWikiAdminLdapGroupEnv environment variable name
	JsWikiAdminLdapGroupEnv string = "LDAP_JSWIKI_ADMIN_GROUP"
	// LdapGroupPrefixEnv environment variable name
	JsWikiLdapGroupPrefixEnv string = "LDAP_JSWIKI_GROUP_PREFIX"
)

const (
	// RequiredFieldErrorMsg template for validate error message if it must be non-empty
	RequiredFieldErrorMsg string = "Environment variable %s must be non empty"

	// MustPositiveErrorMsg template for validate error message if it must be positive
	MustPositiveErrorMsg string = "Value of environment variable %s must be greater than zero"

	// DryRunLogMsg for log dry run mode
	DryRunLogMsg string = "Dry run sync mode: %v"

	// CannotReadResponseBodyMsg is log msg
	CannotReadResponseBodyMsg string = "Cannot read response body: %s"

	// CannotCreateQueryMsg is log msg
	CannotCreateQueryMsg string = "Cannot create graphql query: %s"

	// CannotUnmarshallMsg is log msg
	CannotUnmarshallMsg string = "Cannot unmarshall data: %s"

	// ExpiredPasswordReasonMsg is log msg for expired password ban reason
	ExpiredPasswordReasonMsg string = "Has expired password"
	// DeletedInLdapReasonMsg is log msg for deleted from ldap reason
	DeletedInLdapReasonMsg string = "Deleted in ldap"
	// DisabledOrExcludeFromGroupReasonMsg is log msg for disabled or exclude from access group ban reason
	DisabledOrExcludeFromGroupReasonMsg string = "Disabled in ldap or excluded from access group"
	// BanUserMsg is log msg for ban action
	BanUserMsg string = "User has banned"
	// UnbanUserMsg is log msg for unban action
	UnbanUserMsg string = "User unbanned"
	// DeleteUserMsg is log msg for delete action
	DeleteUserMsg string = "User has deleted"
	// UpdateUserMsg is log msg for delete action
	UpdateUserMsg string = "User updated"

	// ClientLogField is field for client logs
	ClientLogField string = "client"
	// SyncerLogField is field for client logs
	SyncerLogField string = "syncer"
	// GroupLogField is field for client logs
	GroupLogField string = "group"
	// UserLogField is field for client logs
	UserLogField string = "user"
	// ReasonLogField is field for client logs
	ReasonLogField string = "reason"
)

// ErrValidate error type for general validation errors
var ErrValidate error = fmt.Errorf("%s", "Validate error")
