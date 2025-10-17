package gitlab

const (
	// CannotListSSHKeysMsg is log msg
	CannotListSSHKeysMsg string = "Cannot list SSH keys for user %s: %s"

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
