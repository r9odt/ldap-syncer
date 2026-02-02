package gitlab

const (
	// CannotListSSHKeysMsg is log msg
	CannotListSSHKeysMsg string = "Cannot list SSH keys for user: %s"

	// UserIsBotMsg is message for bot users
	UserIsBotMsg string = "User is bot"
	// SaveUserMsg is log msg for save user action
	SaveUserMsg string = "Save user"
	// UpdateAdminFieldMsg is log msg for update is_admin user field
	UpdateAdminFieldMsg string = "Update is_admin %t->%t"
	// UpdateDisplayNameFieldMsg is log msg for update name user field
	UpdateDisplayNameFieldMsg string = "Update name %s->%s"
	// UpdateCanCreateTLGFieldMsg is log msg for update can_create_group user field
	UpdateCanCreateTLGFieldMsg string = "Update can_create_group %t->%t"
	// UpdateProjectLimitFieldMsg is log msg for update projects_limit user field
	UpdateProjectLimitFieldMsg string = "Update projects_limit %d->%d"

	// FreeIPAManagedSSHKeyTitlePrefix is prefix for ssh keys title
	FreeIPAManagedSSHKeyTitlePrefix string = "FreeIPA managed key"
)
