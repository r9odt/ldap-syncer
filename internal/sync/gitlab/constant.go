package gitlab

const (
	// CannotListSSHKeysMsg is log msg
	CannotListSSHKeysMsg string = "Cannot list SSH keys for user: %s"

	// UserIsBotMsg is message for bot users
	UserIsBotMsg string = "User is bot"
	// SaveUserMsg is log msg for save user action
	SaveUserMsg string = "Save user"
	// SaveProjectMsg is log msg for save project action
	SaveProjectMsg string = "Save project"
	// UpdateAdminFieldMsg is log msg for update is_admin user field
	UpdateAdminFieldMsg string = "Update is_admin %t->%t"
	// UpdateDisplayNameFieldMsg is log msg for update name user field
	UpdateDisplayNameFieldMsg string = "Update name %s->%s"
	// UpdateCanCreateTLGFieldMsg is log msg for update can_create_group user field
	UpdateCanCreateTLGFieldMsg string = "Update can_create_group %t->%t"
	// UpdateProjectLimitFieldMsg is log msg for update projects_limit user field
	UpdateProjectLimitFieldMsg string = "Update projects_limit %d->%d"

	// UpdateContainerPolicyEnabledFieldMsg is log msg for update enabled policy field
	UpdateContainerPolicyEnabledFieldMsg string = "Update enabled %v->%v"
	// UpdateContainerPolicyCadenceFieldMsg is log msg for update cadence policy field
	UpdateContainerPolicyCadenceFieldMsg string = "Update cadence %s->%s"
	// UpdateContainerPolicyKeepNFieldMsg is log msg for update keepN policy field
	UpdateContainerPolicyKeepNFieldMsg string = "Update keep_n %d->%d"
	// UpdateContainerPolicyNameRegexKeepFieldMsg is log msg for update name_regex_keep policy field
	UpdateContainerPolicyNameRegexKeepFieldMsg string = "Update name_regex_keep %s->%s"
	// UpdateContainerPolicyOlderThanFieldMsg is log msg for update name_regex policy field
	UpdateContainerPolicyOlderThanFieldMsg string = "Update older_than %s->%s"
	// UpdateContainerPolicyNameRegexDeleteFieldMsg is log msg for update name_regex_delete policy field
	UpdateContainerPolicyNameRegexDeleteFieldMsg string = "Update name_regex_delete %s->%s"

	// SyncRegistryPolicyControlString is a flag for managed policies
	SyncRegistryPolicyControlString = "sync-managed"
	// FreeIPAManagedSSHKeyTitlePrefix is prefix for ssh keys title
	FreeIPAManagedSSHKeyTitlePrefix string = "FreeIPA managed key"
)
