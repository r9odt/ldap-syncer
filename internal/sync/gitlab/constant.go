package gitlab

const (
	// CannotListSSHKeysMsg is log msg for expired password ban reason
	CannotListSSHKeysMsg string = "Cannot list SSH keys for user %s: %s"

	// ExpiredPasswordReasonMsg is log msg for expired password ban reason
	ExpiredPasswordReasonMsg string = "Has expired password"
	// DeletedInLdapReasonMsg is log msg for deleted from ldap ban reason
	DeletedInLdapReasonMsg string = "Deleted in ldap"
	// DisabledOrExcludeFromGroupReasonMsg is log msg for disabled or exclude from access group ban reason
	DisabledOrExcludeFromGroupReasonMsg string = "Disabled in ldap or excluded from access group"
	// BanUserMsg is log msg for ban action
	BanUserMsg string = "User %s has banned. Reason: %s"
	// UnbanUserMsg is log msg for unban action
	UnbanUserMsg string = "User %s unbanned"
	// DeleteUserMsg is log msg for delete action
	DeleteUserMsg string = "User %s has deleted. Reason: %s"

	// UserIsBotMsg is message for bot users
	UserIsBotMsg string = "User %s is bot"
	// SaveUserMsg is log msg for save user action
	SaveUserMsg string = "Save user %s"
	// UpdateAdminFieldMsg is log msg for update is_admin user field
	UpdateAdminFieldMsg string = "User %s, update is_admin %t->%t"
	// UpdateDisplayNameFieldMsg is log msg for update name user field
	UpdateDisplayNameFieldMsg string = "User %s, update name %s->%s"
	// UpdateCanCreateTLGFieldMsg is log msg for update can_create_group user field
	UpdateCanCreateTLGFieldMsg string = "User %s, update can_create_group %t->%t"
	// UpdateProjectLimitFieldMsg is log msg for update is_admin user field
	UpdateProjectLimitFieldMsg string = "User %s, update projects_limit %d->%d"

	// FreeIPAManagedSSHKeyTitlePrefix is prefix for ssh keys title
	FreeIPAManagedSSHKeyTitlePrefix string = "FreeIPA managed key"
)
