package gitlab

import (
	"fmt"
	"strconv"
	"strings"
	"time"

	goldap "github.com/go-ldap/ldap/v3"
	"github.com/r9odt/ldap-syncer/internal/client/ldap"
	"github.com/r9odt/ldap-syncer/internal/constant"
	"github.com/r9odt/ldap-syncer/internal/utils"
	gitlab "gitlab.com/gitlab-org/api/client-go"
)

// Start sync process
func (s *Syncer) Sync() {
	var err error
	s.client, err = gitlab.NewClient(
		s.Token,
		gitlab.WithBaseURL(s.ApiURL),
	)
	if err != nil {
		s.Logger.Errorf("Cannot create gitlab client: %s", err.Error())
		return
	}
	for {
		s.sync()
		select {
		case <-s.Ctx.Done():
			return
		case <-time.After(s.SyncInterval):
		}
	}
}

func (s *Syncer) sync() {
	s.Logger.Infof(constant.DryRunLogMsg, s.IsDryRun)
	s.getGitlabUsersFromLdap()
	s.syncUsers()
	s.syncGroups()
}

func (s *Syncer) getGitlabUsersFromLdap() {
	// Find all users in user group
	allUsersSearchRequest := goldap.NewSearchRequest(
		s.Ldap.LdapUsersBaseDN,
		1, 0, 0, 0, false,
		fmt.Sprintf(ldap.GroupActiveMembersFilter, goldap.EscapeFilter(s.UsersLdapGroup), goldap.EscapeFilter(s.Ldap.LdapGroupsBaseDN)),
		// In-order request attributes
		[]string{
			s.Ldap.LdapUsernameAttr,
			s.Ldap.LdapDisplayNameAttr,
			s.Ldap.LdapSSHKeyAttr,
		},
		nil,
	)

	sr, err := s.Ldap.Connection.Search(allUsersSearchRequest)
	if err != nil {
		s.Logger.Errorf(ldap.CannotSearchLdapUsersForGroupMsg,
			s.UsersLdapGroup, err.Error())
		return
	}

	for _, en := range sr.Entries {
		username := ""
		user := s.newUser()
		user.dn = en.DN
		for _, attr := range en.Attributes {
			switch attr.Name {
			case s.Ldap.LdapUsernameAttr:
				username = attr.Values[0]
			case s.Ldap.LdapDisplayNameAttr:
				user.displayName = attr.Values[0]
			case s.Ldap.LdapSSHKeyAttr:
				user.sshKeys = append(user.sshKeys, attr.Values...)
			}
		}
		if len(username) > 0 {
			s.ldapAllUsers[username] = user
			s.Logger.Debugf("Created ldap user %s object %#v %#v", username, user, s.ldapAllUsers[username])
		}
	}

	// Find all users in admin group
	adminUsersSearchRequest := goldap.NewSearchRequest(
		s.Ldap.LdapUsersBaseDN,
		1, 0, 0, 0, false,
		fmt.Sprintf(ldap.GroupActiveMembersFilter, goldap.EscapeFilter(s.AdminLdapGroup), goldap.EscapeFilter(s.Ldap.LdapGroupsBaseDN)),
		[]string{
			s.Ldap.LdapUsernameAttr,
		},
		nil,
	)

	sr, err = s.Ldap.Connection.Search(adminUsersSearchRequest)
	if err != nil {
		s.Logger.Errorf(ldap.CannotSearchLdapUsersForGroupMsg,
			s.AdminLdapGroup, err.Error())
		return
	}

	for _, en := range sr.Entries {
		username := ""
		for _, attr := range en.Attributes {
			switch attr.Name {
			case s.Ldap.LdapUsernameAttr:
				username = attr.Values[0]
				break
			}
		}
		if len(username) == 0 {
			continue
		}
		if u, ok := s.ldapAllUsers[username]; ok {
			u.isAdmin = true
			s.Logger.Debugf("Set ldap user %s as admin", username)
		}
	}

	// Find all expired users in users group
	expireDate := time.Now().AddDate(0, 0, -int(s.Ldap.LdapExpiredUsersDeltaDays)).Format("20060102150405")
	expiredUsersSearchRequest := goldap.NewSearchRequest(
		s.Ldap.LdapUsersBaseDN,
		1, 0, 0, 0, false,
		fmt.Sprintf(ldap.GroupExpiredMembersFilter, goldap.EscapeFilter(s.UsersLdapGroup), goldap.EscapeFilter(s.Ldap.LdapGroupsBaseDN), goldap.EscapeFilter(expireDate)),
		[]string{
			s.Ldap.LdapUsernameAttr,
		},
		nil,
	)

	sr, err = s.Ldap.Connection.Search(expiredUsersSearchRequest)
	if err != nil {
		s.Logger.Errorf("Cannot search users for ldap group %s: %s",
			s.UsersLdapGroup, err.Error())
		return
	}

	for _, en := range sr.Entries {
		username := ""
		for _, attr := range en.Attributes {
			switch attr.Name {
			case s.Ldap.LdapUsernameAttr:
				username = attr.Values[0]
				break
			}
		}
		if len(username) > 0 {
			s.ldapExpiredUsers[username] = true
			s.Logger.Debugf("Found expired password for ldap user %s", username)
		}
	}
}

func (s *Syncer) syncProjectLimits() {
	var (
		err    error
		filter string = fmt.Sprintf("(cn=%s*)", goldap.EscapeFilter(s.ProjectLimitLdapGroupPrefix))
	)
	// Find all groups by prefix
	groupSearchRequest := goldap.NewSearchRequest(
		s.Ldap.LdapGroupsBaseDN,
		1, 0, 0, 0, false,
		filter,
		[]string{
			s.Ldap.LdapGroupnameAttr,
		},
		nil,
	)

	gr, err := s.Ldap.Connection.Search(groupSearchRequest)
	if err != nil {
		s.Logger.Errorf("Cannot search ldap group with filter %s: %s",
			filter, err.Error())
		return
	}

	for _, en := range gr.Entries {
		groupname := ""
		for _, attr := range en.Attributes {
			switch attr.Name {
			case s.Ldap.LdapGroupnameAttr:
				groupname = attr.Values[0]
				break
			}
		}
		if len(groupname) == 0 {
			continue
		}
		limit := s.getProjectLimitFromGroupName(groupname)
		s.Logger.Debugf("Find ldap group %s with limit %d", groupname, limit)

		// Find all users in group
		membersSearchRequest := goldap.NewSearchRequest(
			s.Ldap.LdapUsersBaseDN,
			1, 0, 0, 0, false,
			fmt.Sprintf(ldap.GroupActiveMembersFilter, goldap.EscapeFilter(groupname), goldap.EscapeFilter(s.Ldap.LdapGroupsBaseDN)),
			[]string{
				s.Ldap.LdapUsernameAttr,
			},
			nil,
		)

		sr, err := s.Ldap.Connection.Search(membersSearchRequest)
		if err != nil {
			s.Logger.Errorf(ldap.CannotSearchLdapUsersForGroupMsg,
				s.UsersLdapGroup, err.Error())
			return
		}

		for _, en := range sr.Entries {
			username := ""
			for _, attr := range en.Attributes {
				switch attr.Name {
				case s.Ldap.LdapUsernameAttr:
					username = attr.Values[0]
					break
				}
			}
			if len(username) == 0 {
				continue
			}
			if u, ok := s.ldapAllUsers[username]; ok {
				if u.projectLimit < limit {
					u.projectLimit = limit
					s.Logger.Debugf("Set ldap user %s project limit %d", username, limit)
				}
			}
		}
	}
}

func (s *Syncer) syncCanCreateTLGFlag() error {
	if len(s.UserCanCreateTLGLdapGroup) == 0 {
		return nil
	}
	// Find all users in group
	usersSearchRequest := goldap.NewSearchRequest(
		s.Ldap.LdapUsersBaseDN,
		1, 0, 0, 0, false,
		fmt.Sprintf(ldap.GroupActiveMembersFilter, goldap.EscapeFilter(s.UserCanCreateTLGLdapGroup), goldap.EscapeFilter(s.Ldap.LdapGroupsBaseDN)),
		[]string{
			s.Ldap.LdapUsernameAttr,
		},
		nil,
	)

	sr, err := s.Ldap.Connection.Search(usersSearchRequest)
	if err != nil {
		s.Logger.Errorf(ldap.CannotSearchLdapUsersForGroupMsg,
			s.UsersLdapGroup, err.Error())
		return err
	}

	for _, en := range sr.Entries {
		username := ""
		for _, attr := range en.Attributes {
			switch attr.Name {
			case s.Ldap.LdapUsernameAttr:
				username = attr.Values[0]
				break
			}
		}
		if len(username) == 0 {
			continue
		}
		if u, ok := s.ldapAllUsers[username]; ok {
			u.canCreateTLG = true
			s.Logger.Debugf("Set can create TLD for ldap user %s", username)

		}
	}

	return nil
}

func (s *Syncer) syncUsers() {
	s.Logger.Infof("Users sync start")
	s.syncProjectLimits()
	s.syncCanCreateTLGFlag()
	opt := &gitlab.ListUsersOptions{
		ListOptions: gitlab.ListOptions{
			PerPage: 100,
			Page:    1,
		},
	}
	for {
		glusers, resp, err := s.client.Users.ListUsers(opt, gitlab.WithContext(s.Ctx))
		if err != nil {
			s.Logger.Errorf("Cannot list gitlab users: %s", err.Error())
			return
		}

		select {
		case <-s.Ctx.Done():
			s.Logger.Warning("Interrupt users sync")
			return
		default:
			s.syncGitlabUsersParameters(glusers)
		}

		if resp.NextPage == 0 {
			break
		}
		opt.Page = resp.NextPage
	}
	s.Logger.Infof("Users sync done")
}

func (s *Syncer) syncGitlabUsersParameters(glusers []*gitlab.User) {
	for _, u := range glusers {
		s.Logger.Debugf("Sync user %s", u.Username)
		if u.Bot {
			s.Logger.Infof(UserIsBotMsg, u.Username)
			continue
		}

		if !s.isUserManagedByLdapProvider(u) {
			s.Logger.Infof("User %s is not managed by ldap %s", u.Username, s.LdapProvider)
			continue
		}

		if _, ok := s.ldapAllUsers[u.Username]; !ok {
			if s.Ldap.IsLdapUserExist(u.Username) {
				s.banUser(u, DisabledOrExcludeFromGroupReasonMsg)
			} else {
				s.deleteUser(u, DeletedInLdapReasonMsg)
			}
			continue
		}

		if _, ok := s.ldapExpiredUsers[u.Username]; ok {
			s.banUser(u, ExpiredPasswordReasonMsg)
			continue
		}

		s.unbanUser(u)

		needUpdate := false
		user := s.ldapAllUsers[u.Username]
		modifyOptions := &gitlab.ModifyUserOptions{}
		if user.isAdmin != u.IsAdmin {
			modifyOptions.Admin = &user.isAdmin
			needUpdate = true
			s.Logger.Infof(UpdateAdminFieldMsg, u.Username,
				u.IsAdmin, user.isAdmin)
		}

		if user.displayName != u.Name {
			modifyOptions.Name = &user.displayName
			needUpdate = true
			s.Logger.Infof(UpdateAdminFieldMsg, u.Username,
				u.Name, user.displayName)
		}

		if user.canCreateTLG != u.CanCreateGroup {
			modifyOptions.CanCreateGroup = &user.canCreateTLG
			needUpdate = true
			s.Logger.Infof(UpdateCanCreateTLGFieldMsg, u.Username,
				u.CanCreateGroup, user.canCreateTLG)
		}

		if user.projectLimit != u.ProjectsLimit {
			modifyOptions.ProjectsLimit = &user.projectLimit
			needUpdate = true
			s.Logger.Infof(UpdateProjectLimitFieldMsg, u.Username,
				u.ProjectsLimit, user.projectLimit)
		}

		if needUpdate {
			if !s.IsDryRun {
				s.client.Users.ModifyUser(u.ID, modifyOptions, gitlab.WithContext(s.Ctx))
			}
			s.Logger.Infof(SaveUserMsg, u.Username)
		}

		s.syncSSHKeys(u)
	}
}

func (s *Syncer) banUser(user *gitlab.User, reason string) {
	if user.State != "active" {
		return
	}
	if !s.IsDryRun {
		s.client.Users.BanUser(user.ID, gitlab.WithContext(s.Ctx))
	}
	s.Logger.Infof(BanUserMsg, user.Username, reason)
}

func (s *Syncer) unbanUser(user *gitlab.User) {
	if user.State != "banned" {
		return
	}
	if !s.IsDryRun {
		s.client.Users.UnbanUser(user.ID, gitlab.WithContext(s.Ctx))
	}
	s.Logger.Infof(UnbanUserMsg, user.Username)
}

func (s *Syncer) deleteUser(user *gitlab.User, reason string) {
	if !s.IsDryRun {
		s.client.Users.DeleteUser(user.ID, gitlab.WithContext(s.Ctx))
	}
	s.Logger.Infof(DeleteUserMsg, user.Username, reason)
}

// syncSSHKeys is sync procedure ssh keys (Only one direction FreeIPA -> Gitlab)
func (s *Syncer) syncSSHKeys(user *gitlab.User) {
	u := s.ldapAllUsers[user.Username]

	opt := &gitlab.ListSSHKeysForUserOptions{
		PerPage: 100,
		Page:    1,
	}

	var gitlabSSHKeys []*gitlab.SSHKey = make([]*gitlab.SSHKey, 0)

	for {
		keys, resp, err := s.client.Users.ListSSHKeysForUser(user.ID, opt, gitlab.WithContext(s.Ctx))
		if err != nil {
			s.Logger.Errorf(CannotListSSHKeysMsg, user.Username, err.Error())
			return
		}

		gitlabSSHKeys = append(gitlabSSHKeys, keys...)

		if resp.NextPage == 0 {
			break
		}

		opt.Page = resp.NextPage
	}

	keyDate := time.Now().Format("2006-01-02")
	for _, key := range u.sshKeys {
		ipaKeyArray := strings.Fields(key)
		if len(ipaKeyArray) < 2 {
			s.Logger.Warningf("One of ldap ssh keys for user %s doesn.t have protocol or key", user.Username)
			continue
		}

		gitlabKeyID := s.isIPAKeyInGitLabKeys(ipaKeyArray, gitlabSSHKeys)
		if gitlabKeyID > 0 {
			s.Logger.Infof("Found existing ssh key for user %s with id %d", user.Username, gitlabKeyID)
			continue
		}
		title := fmt.Sprintf("%s %s", FreeIPAManagedSSHKeyTitlePrefix, keyDate)
		if len(ipaKeyArray) > 2 {
			title = fmt.Sprintf("%s %s", title, ipaKeyArray[2])
		}

		keyid := -1
		if !s.IsDryRun {
			keyOptions := &gitlab.AddSSHKeyOptions{
				Title: &title,
				Key:   &key,
			}

			_, _, err := s.client.Users.AddSSHKeyForUser(user.ID, keyOptions, gitlab.WithContext(s.Ctx))
			if err != nil {
				s.Logger.Errorf("Cannot add key %s for user %s: %s", key, user.Username, err.Error())
				continue
			}
		}
		s.Logger.Infof("Add key %d for user %s: %s", keyid, user.Username, title)
	}

	for _, gitlabKey := range gitlabSSHKeys {
		if !strings.HasPrefix(gitlabKey.Title, FreeIPAManagedSSHKeyTitlePrefix) {
			continue
		}

		isIPAKey := s.isGitLabKeyInIPAKeys(u.sshKeys, gitlabKey)
		if isIPAKey {
			continue
		}

		if !s.IsDryRun {
			_, err := s.client.Users.DeleteSSHKeyForUser(user.ID, gitlabKey.ID, gitlab.WithContext(s.Ctx))
			if err != nil {
				s.Logger.Errorf("Cannot delete key %d for user %s: %s", user.Username, gitlabKey.ID, err.Error())
			}
		}
		s.Logger.Infof("Remove key %d for user %s: %s", gitlabKey.ID, user.Username, gitlabKey.Title)
	}
}

func (s *Syncer) isGitLabKeyInIPAKeys(ipaKeys []string, gitlabKey *gitlab.SSHKey) bool {
	gitlabKeyArray := strings.Fields(gitlabKey.Key)
	if len(gitlabKeyArray) < 2 {
		return false
	}
	for _, ipaKey := range ipaKeys {
		ipaKeyArray := strings.Fields(ipaKey)
		if len(ipaKeyArray) < 2 {
			continue
		}
		// indicies: 0 - protocol, 1 - key
		if gitlabKeyArray[0] == ipaKeyArray[0] && gitlabKeyArray[1] == ipaKeyArray[1] {
			return true
		}
	}
	return false
}

func (s *Syncer) isIPAKeyInGitLabKeys(ipaKeyArray []string, gitlabKeys []*gitlab.SSHKey) int {
	for _, gitlabKey := range gitlabKeys {
		gitlabKeyArray := strings.Fields(gitlabKey.Key)
		if len(gitlabKeyArray) < 2 {
			continue
		}
		// indicies: 0 - protocol, 1 - key
		if gitlabKeyArray[0] == ipaKeyArray[0] && gitlabKeyArray[1] == ipaKeyArray[1] {
			return gitlabKey.ID
		}
	}

	return -1
}

// Return projects limit by group suffix
func (s *Syncer) getProjectLimitFromGroupName(group string) int {
	limit := s.UserDefaultProjectLimit

	if group == "" {
		return limit
	}

	lastDashIndex := strings.LastIndex(group, "-")
	if lastDashIndex == len(group)-1 {
		return limit
	}

	numberPart := group[lastDashIndex+1:]

	if num, err := strconv.Atoi(numberPart); err == nil {
		return num
	}
	return limit
}

// Return access level by group suffix
func (s *Syncer) getLdapGroupAccessLevelByName(group string) gitlab.AccessLevelValue {
	// Return access level by group suffix
	if strings.HasSuffix(group, "-owner") {
		return gitlab.OwnerPermissions
	}
	if strings.HasSuffix(group, "-maintainer") {
		return gitlab.MaintainerPermissions
	}
	if strings.HasSuffix(group, "-developer") {
		return gitlab.DeveloperPermissions
	}
	if strings.HasSuffix(group, "-reporter") {
		return gitlab.ReporterPermissions
	}
	if strings.HasSuffix(group, "-guest") {
		return gitlab.GuestPermissions
	}
	return -s.stringToGitlabPermissions(s.GroupDefaultAccessLevel)
}

// Return access level by name
func (s *Syncer) stringToGitlabPermissions(group string) gitlab.AccessLevelValue {
	switch group {
	case "owner":
		return gitlab.OwnerPermissions
	case "maintainer":
		return gitlab.MaintainerPermissions
	case "developer":
		return gitlab.DeveloperPermissions
	case "reporter":
		return gitlab.ReporterPermissions
	case "guest":
		return gitlab.GuestPermissions
	default:
	}

	return gitlab.ReporterPermissions
}

func (s *Syncer) syncGroups() {
	s.Logger.Infof("Groups sync start")
	opt := &gitlab.ListGroupsOptions{
		ListOptions: gitlab.ListOptions{
			PerPage: 100,
			Page:    1,
		},
	}
	for {
		glgroups, resp, err := s.client.Groups.ListGroups(opt, gitlab.WithContext(s.Ctx))
		if err != nil {
			s.Logger.Errorf("Cannot list gitlab groups: %s", err.Error())
			return
		}

		select {
		case <-s.Ctx.Done():
			s.Logger.Warning("Interrupt users sync")
			return
		default:
			s.syncGitlabGroupsParameters(glgroups)
		}

		if resp.NextPage == 0 {
			break
		}
		opt.Page = resp.NextPage
	}
	s.Logger.Infof("Groups sync done")
}

func (s *Syncer) syncGitlabGroupsParameters(glgroups []*gitlab.Group) {
	for _, g := range glgroups {
		s.Logger.Infof("Sync group %s", g.FullPath)
		ldapMembers, isExist := s.getGitlabGroupLdapMembers(g)
		if !isExist {
			continue
		}

		gitlabMembers := s.getGitLabGroupMembers(g)
		for _, m := range gitlabMembers {
			if _, ok := ldapMembers[m.Username]; ok {
				continue
			}

			user := s.getGitLabUserByID(m.ID)
			if user.Bot {
				s.Logger.Infof(UserIsBotMsg, user.Username)
				continue
			}

			if !s.isUserManagedByLdapProvider(user) {
				s.Logger.Infof("User %s is not managed by ldap %s", user.Username, s.LdapProvider)
				continue
			}

			s.removeGroupMember(g, user)
		}

		var rootMember *gitlab.GroupMember = nil
		for _, m := range gitlabMembers {
			if m.Username == "root" {
				rootMember = m
				break
			}
		}

		root := s.getGitLabUserByName("root")
		if rootMember == nil {
			// Root user must be owner on all groups which synced
			s.createGroupMember(g, root, gitlab.OwnerPermissions)
		}

		if rootMember != nil {
			s.fixGroupMemberAccess(g, rootMember, gitlab.OwnerPermissions)
		}

		for username, level := range ldapMembers {
			if m, ok := gitlabMembers[username]; ok {
				s.fixGroupMemberAccess(g, m, level)
				continue
			}

			u := s.getGitLabUserByName(username)
			if u == nil {
				s.Logger.Warningf("User %s can.t be added to group %s because it not exist in gitlab. User need to login before sync.", username, g.FullPath)
				continue
			}

			s.createGroupMember(g, u, level)
		}
	}
}

func (s *Syncer) removeGroupMember(g *gitlab.Group, u *gitlab.User) {
	if !s.IsDryRun {
		_, err := s.client.GroupMembers.RemoveGroupMember(g.ID, u.ID, &gitlab.RemoveGroupMemberOptions{}, gitlab.WithContext(s.Ctx))
		if err != nil {
			s.Logger.Errorf("Cannot remove group %s member %s: %s", g.FullPath, u.Username, err.Error())
			return
		}
	}
	s.Logger.Infof("Remove %s from group %s", u.Username, g.FullPath)
}

func (s *Syncer) createGroupMember(g *gitlab.Group, u *gitlab.User, level gitlab.AccessLevelValue) {
	var accessLevel gitlab.AccessLevelValue = gitlab.AccessLevelValue(utils.AbsInt(int(level)))
	if !s.IsDryRun {
		opt := &gitlab.AddGroupMemberOptions{
			UserID:      &u.ID,
			AccessLevel: &accessLevel,
		}
		_, _, err := s.client.GroupMembers.AddGroupMember(g.ID, opt, gitlab.WithContext(s.Ctx))
		if err != nil {
			s.Logger.Errorf("Cannot create group %s member %s: %s", g.FullPath, u.Username, err.Error())
			return
		}
	}
	s.Logger.Infof("Add %s to group %s with level %d", u.Username, g.FullPath, accessLevel)
}

func (s *Syncer) fixGroupMemberAccess(g *gitlab.Group, u *gitlab.GroupMember, level gitlab.AccessLevelValue) {
	var accessLevel gitlab.AccessLevelValue = gitlab.AccessLevelValue(utils.AbsInt(int(level)))
	if accessLevel == u.AccessLevel {
		return
	}
	if !s.IsDryRun {
		opt := &gitlab.EditGroupMemberOptions{
			AccessLevel: &accessLevel,
		}
		_, _, err := s.client.GroupMembers.EditGroupMember(g.ID, u.ID, opt, gitlab.WithContext(s.Ctx))
		if err != nil {
			s.Logger.Errorf("Cannot create group %s member %s: %s", g.FullPath, u.Username, err.Error())
			return
		}
	}
	s.Logger.Infof("Update access level for %s in group %s: %d->%d", u.Username, g.FullPath, u.AccessLevel, accessLevel)
}

func (s *Syncer) isUserManagedByLdapProvider(user *gitlab.User) bool {
	ldapProviderUserDN := ""
	for _, idn := range user.Identities {
		if idn.Provider == s.LdapProvider {
			ldapProviderUserDN = idn.ExternUID
			break
		}
	}
	if len(ldapProviderUserDN) == 0 {
		return false
	}
	return true
}

func (s *Syncer) getGitLabUserByID(id int) *gitlab.User {
	gluser, _, err := s.client.Users.GetUser(id, gitlab.GetUsersOptions{}, gitlab.WithContext(s.Ctx))

	if err != nil {
		s.Logger.Errorf("Cannot list gitlab users: %s", err.Error())
		return nil
	}
	return gluser
}

func (s *Syncer) getGitLabUserByName(name string) *gitlab.User {
	opts := &gitlab.ListUsersOptions{
		Username: &name,
	}
	glusers, _, err := s.client.Users.ListUsers(opts, gitlab.WithContext(s.Ctx))

	if err != nil {
		s.Logger.Errorf("Cannot list gitlab users: %s", err.Error())
		return nil
	}

	if len(glusers) == 0 {
		return nil
	}

	return glusers[0]
}

func (s *Syncer) getGitLabGroupMembers(group *gitlab.Group) map[string]*gitlab.GroupMember {
	members := make(map[string]*gitlab.GroupMember)

	// Получаем всех членов группы с пагинацией
	opt := &gitlab.ListGroupMembersOptions{
		ListOptions: gitlab.ListOptions{
			PerPage: 100,
			Page:    1,
		},
	}

	for {
		gitlabMembers, resp, err := s.client.Groups.ListGroupMembers(group.ID, opt, gitlab.WithContext(s.Ctx))
		if err != nil {
			s.Logger.Errorf("Cannot list gitlab group %s members: %s", group.FullPath, err.Error())
			return members
		}

		for _, gm := range gitlabMembers {
			members[gm.Username] = gm
		}

		if resp.NextPage == 0 {
			break
		}
		opt.Page = resp.NextPage
	}

	return members
}

func (s *Syncer) getGitlabGroupLdapMembers(glgroup *gitlab.Group) (map[string]gitlab.AccessLevelValue, bool) {
	isExist := false
	members := make(map[string]gitlab.AccessLevelValue)
	ldapGroupName := strings.ReplaceAll(glgroup.FullPath, "/", "--")
	prefix := fmt.Sprintf("cn=%s%s", s.LdapGroupPrefix, ldapGroupName)
	filter := fmt.Sprintf("(|(%[1]s)(%[1]s-owner)(%[1]s-maintainer)(%[1]s-developer)(%[1]s-reporter)(%[1]s-guest))", goldap.EscapeFilter(prefix))

	// Find groups
	groupSearchRequest := goldap.NewSearchRequest(
		s.Ldap.LdapGroupsBaseDN,
		1, 0, 0, 0, false,
		filter,
		[]string{
			s.Ldap.LdapGroupnameAttr,
		},
		nil,
	)

	sr, err := s.Ldap.Connection.Search(groupSearchRequest)
	if err != nil {
		s.Logger.Errorf(ldap.CannotSearchLdapGroupsMsg, filter, err.Error())
		return members, isExist
	}

	for _, en := range sr.Entries {
		groupname := ""
		for _, attr := range en.Attributes {
			switch attr.Name {
			case s.Ldap.LdapGroupnameAttr:
				groupname = attr.Values[0]
				break
			}
		}
		if len(groupname) == 0 {
			continue
		}
		isExist = true

		accessLevel := s.getLdapGroupAccessLevelByName(groupname)

		// Find members
		usersSearchRequest := goldap.NewSearchRequest(
			s.Ldap.LdapUsersBaseDN,
			1, 0, 0, 0, false,
			fmt.Sprintf(ldap.GroupActiveMembersFilter, goldap.EscapeFilter(groupname), goldap.EscapeFilter(s.Ldap.LdapGroupsBaseDN)),
			[]string{
				s.Ldap.LdapUsernameAttr,
			},
			nil,
		)

		gsr, err := s.Ldap.Connection.Search(usersSearchRequest)
		if err != nil {
			s.Logger.Errorf(ldap.CannotSearchLdapUsersForGroupMsg,
				s.UsersLdapGroup, err.Error())
			return members, isExist
		}

		for _, en := range gsr.Entries {
			username := ""
			for _, attr := range en.Attributes {
				switch attr.Name {
				case s.Ldap.LdapUsernameAttr:
					username = attr.Values[0]
					break
				}
			}
			if len(username) > 0 {
				members[username] = accessLevel
			}
		}
	}

	return members, isExist
}
