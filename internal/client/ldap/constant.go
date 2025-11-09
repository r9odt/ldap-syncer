package ldap

const (
	// AttrFilter return query for filtering by attribute.
	// Uses attr name and value.
	// Example: (uid=username)
	AttrFilter string = "(%s=%s)"

	// GroupActiveMembersFilter return filter for ldap to get
	// non-blocked members of group users.
	// Uses group name and base group dn
	GroupActiveMembersFilter string = "(&(memberof=cn=%s,%s)(!(nsaccountlock=TRUE)))"

	// GroupExpiredMembersFilter return filter for ldap to get
	// blocked members of group users.
	// Uses group name, base group dn and expire date in "20060102150405" format.
	GroupExpiredMembersFilter string = "(&(memberof=cn=%s,%s)(!(nsaccountlock=TRUE))(krbPasswordExpiration<=%sZ))"

	// CannotSearchLdapUsersForGroupMsg log message for search errors
	CannotSearchLdapUsersForGroupMsg string = "Can.t search ldap users for group: %s"

	// CannotSearchLdapGroupsMsg is message for group ldap search error
	CannotSearchLdapGroupsMsg string = "Can.t search ldap groups with filter %s: %s"
)
