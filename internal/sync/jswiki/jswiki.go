package jswiki

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	goldap "github.com/go-ldap/ldap/v3"

	"github.com/r9odt/ldap-syncer/internal/client/ldap"
	"github.com/r9odt/ldap-syncer/internal/constant"
	"github.com/r9odt/ldap-syncer/internal/types"
)

// Start sync process
func (s *Syncer) Sync() {
	if !s.Enabled {
		s.Logger.Info("Sync disabled")
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
	var err error
	err = s.getJsWikiUsersFromLdap()
	if err != nil {
		return
	}
	err = s.getJsWikiUsers()
	if err != nil {
		return
	}
	err = s.getJsWikiGroups()
	if err != nil {
		return
	}

	s.syncUsers()
	s.syncGroups()
}

func (s *Syncer) syncUsers() {
	s.Logger.Infof("Users sync start")
	for _, u := range s.jswikiUsers {
		s.Logger.Debugf("Sync user %s", u.Name)
		if u.IsSystem {
			s.Logger.Infof("User %s is system", u.Name)
			continue
		}
		if len(u.ProviderId) == 0 {
			s.Logger.Infof("User %s is not managed by ldap", u.Name)
			continue
		}

		if _, ok := s.ldapAllUsers[u.ProviderId]; !ok {
			if s.Ldap.IsLdapUserExist(u.ProviderId) {
				_ = s.disableUser(u, constant.DisabledOrExcludeFromGroupReasonMsg)
			} else {
				_ = s.deleteUser(u, constant.DeletedInLdapReasonMsg)
			}
			continue
		}

		_ = s.enableUser(u)

		needUpdate := false
		if u.Timezone != s.UsersTZ {
			needUpdate = true
			s.Logger.Infof(UpdateTZFieldMsg, u.ProviderId,
				u.Timezone, s.UsersTZ)
			u.Timezone = s.UsersTZ
		}
		if needUpdate {
			_ = s.updateUser(u)
		}
	}
	s.Logger.Infof("Users sync done")
}

func (s *Syncer) updateUser(user *JsWikiUser) error {
	if !s.IsDryRun {
		jsWikiReq, err := json.Marshal(types.NewGraphqlQuery(fmt.Sprintf(JsWikiUpdateUserQuery, user.Id, user.Timezone)))
		if err != nil {
			s.Logger.Errorf(constant.CannotCreateQueryMsg, err.Error())
			return err
		}

		_, err = s.sendGraphqlReq(jsWikiReq)
		if err != nil {
			return err
		}
	}
	s.Logger.Infof(constant.UpdateUserMsg, user.ProviderId)
	return nil
}

func (s *Syncer) disableUser(user *JsWikiUser, reason string) error {
	if !user.IsActive {
		return nil
	}
	if !s.IsDryRun {
		jsWikiReq, err := json.Marshal(types.NewGraphqlQuery(fmt.Sprintf(JsWikiDeactivateUserQuery, user.Id)))
		if err != nil {
			s.Logger.Errorf(constant.CannotCreateQueryMsg, err.Error())
			return err
		}

		_, err = s.sendGraphqlReq(jsWikiReq)
		if err != nil {
			return err
		}
	}
	s.Logger.Infof(constant.DeleteUserMsg, user.ProviderId, reason)
	return nil
}

func (s *Syncer) enableUser(user *JsWikiUser) error {
	if user.IsActive {
		return nil
	}
	if !s.IsDryRun {
		jsWikiReq, err := json.Marshal(types.NewGraphqlQuery(fmt.Sprintf(JsWikiActivateUserQuery, user.Id)))
		if err != nil {
			s.Logger.Errorf(constant.CannotCreateQueryMsg, err.Error())
			return err
		}

		_, err = s.sendGraphqlReq(jsWikiReq)
		if err != nil {
			return err
		}
	}
	s.Logger.Infof(constant.DeleteUserMsg, user.ProviderId)
	return nil
}

func (s *Syncer) deleteUser(user *JsWikiUser, reason string) error {
	if !s.IsDryRun {
		jsWikiReq, err := json.Marshal(types.NewGraphqlQuery(fmt.Sprintf(JsWikiDeleteUserQuery, user.Id)))
		if err != nil {
			s.Logger.Errorf(constant.CannotCreateQueryMsg, err.Error())
			return err
		}

		_, err = s.sendGraphqlReq(jsWikiReq)
		if err != nil {
			return err
		}
	}
	s.Logger.Infof(constant.DeleteUserMsg, user.ProviderId, reason)
	return nil
}

func (s *Syncer) syncGroups() {
	s.Logger.Infof("Groups sync start")
	rootMemberId := -1
	for _, m := range s.jswikiUsers {
		if s.jswikiUsers[m.Id].Name == "Administrator" {
			rootMemberId = m.Id
			break
		}
	}
	for _, g := range s.jswikiGroups {
		s.Logger.Infof("Sync group %s", g.Name)

		ldapMembers, isExist := s.getJsWikiGroupLdapMembers(g.Name)
		if !isExist {
			continue
		}

		hasRootMember := false
		for _, m := range g.Users {
			if _, ok := ldapMembers[m.Id]; ok {
				continue
			}
			if m.Id == 1 { // Administrator has id = 1
				hasRootMember = true
			}
			if m.IsSystem {
				s.Logger.Infof("User %s is system", m.Name)
				continue
			}
			if len(s.jswikiUsers[m.Id].ProviderId) == 0 {
				s.Logger.Infof("User %s is not managed by ldap", s.jswikiUsers[m.Id].Name)
				continue
			}

			_ = s.unassignGroup(g.Id, m.Id)
		}

		if g.Name == "Administrators" && !hasRootMember && rootMemberId >= 0 {
			_ = s.assignGroup(g.Id, rootMemberId)
		}

		for mid := range ldapMembers {
			if _, ok := g.usersMap[mid]; ok {
				continue
			}
			_ = s.assignGroup(g.Id, mid)
		}
	}
	s.Logger.Infof("Groups sync done")
}

func (s *Syncer) unassignGroup(gid, uid int) error {
	if !s.IsDryRun {
		jsWikiReq, err := json.Marshal(types.NewGraphqlQuery(fmt.Sprintf(JsWikiUnassignGroupQuery, gid, uid)))
		if err != nil {
			s.Logger.Errorf(constant.CannotCreateQueryMsg, err.Error())
			return err
		}

		_, err = s.sendGraphqlReq(jsWikiReq)
		if err != nil {
			return err
		}
	}
	s.Logger.Infof(UnassignGroupMsg, s.jswikiUsers[uid].ProviderId, s.jswikiGroups[gid].Name)
	return nil
}

func (s *Syncer) assignGroup(gid, uid int) error {
	if !s.IsDryRun {
		jsWikiReq, err := json.Marshal(types.NewGraphqlQuery(fmt.Sprintf(JsWikiAssignGroupQuery, gid, uid)))
		if err != nil {
			s.Logger.Errorf(constant.CannotCreateQueryMsg, err.Error())
			return err
		}

		_, err = s.sendGraphqlReq(jsWikiReq)
		if err != nil {
			return err
		}
	}
	uname := s.jswikiUsers[uid].Name
	if len(s.jswikiUsers[uid].ProviderId) > 0 {
		uname = s.jswikiUsers[uid].ProviderId
	}
	s.Logger.Infof(AssignGroupMsg, uname, s.jswikiGroups[gid].Name)
	return nil
}

func (s *Syncer) setHeaders(req *http.Request) {
	req.Header.Set("authorization", fmt.Sprintf("Bearer %s", s.Token))
	req.Header.Set("content-type", "application/json")
}

func (s *Syncer) getJsWikiGroups() error {
	var err error
	jsWikiReq, err := json.Marshal(types.NewGraphqlQuery(JsWikiGroupListQuery))
	if err != nil {
		s.Logger.Errorf(constant.CannotCreateQueryMsg, err.Error())
		return err
	}

	data, err := s.sendGraphqlReq(jsWikiReq)
	if err != nil {
		return err
	}

	for _, gr := range data.Data.Groups.List {
		g, err := s.getJsWikiGroupByID(gr.Id)
		if err == nil {
			s.jswikiGroups[g.Id] = g
			s.jswikiGroups[g.Id].usersMap = make(map[int]bool)
			for _, u := range g.Users {
				s.jswikiGroups[g.Id].usersMap[u.Id] = true
			}
		}
	}

	return nil
}

func (s *Syncer) getJsWikiGroupByID(id int) (*JsWikiGroup, error) {
	var err error
	jsWikiReq, err := json.Marshal(types.NewGraphqlQuery(fmt.Sprintf(JsWikiGroupSingleQuery, id)))
	if err != nil {
		s.Logger.Errorf(constant.CannotCreateQueryMsg, err.Error())
		return nil, err
	}

	data, err := s.sendGraphqlReq(jsWikiReq)
	if err != nil {
		return nil, err
	}

	return &data.Data.Groups.Single, nil
}

func (s *Syncer) getJsWikiUserByID(id int) (*JsWikiUser, error) {
	var err error
	jsWikiReq, err := json.Marshal(types.NewGraphqlQuery(fmt.Sprintf(JsWikiUserSingleQuery, id)))
	if err != nil {
		s.Logger.Errorf(constant.CannotCreateQueryMsg, err.Error())
		return nil, err
	}

	data, err := s.sendGraphqlReq(jsWikiReq)
	if err != nil {
		return nil, err
	}

	return &data.Data.Users.Single, nil
}

func (s *Syncer) getJsWikiUsers() error {
	var err error
	jsWikiReq, err := json.Marshal(types.NewGraphqlQuery(JsWikiUserListQuery))
	if err != nil {
		s.Logger.Errorf(constant.CannotCreateQueryMsg, err.Error())
		return err
	}

	data, err := s.sendGraphqlReq(jsWikiReq)
	if err != nil {
		return err
	}

	for _, us := range data.Data.Users.List {
		u, err := s.getJsWikiUserByID(us.Id)
		if err == nil {
			s.jswikiUsers[u.Id] = u
			if len(u.ProviderId) > 0 {
				// Save link to user object
				s.ldapAllUsers[u.ProviderId].id = u.Id
			}
		}
	}

	return nil
}

func (s *Syncer) sendGraphqlReq(r []byte) (*JsWikiGraphqlResponse, error) {
	req, err := http.NewRequestWithContext(s.Ctx, http.MethodPost, s.ApiURL, strings.NewReader(string(r)))
	if err != nil {
		s.Logger.Errorf("Cannot create request to search jswiki users: %s", err.Error())
		return nil, err
	}

	s.setHeaders(req)

	resp, err := s.client.Do(req)
	if err != nil {
		s.Logger.Errorf("Cannot do request to search jswiki users: %s", err.Error())
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		s.Logger.Errorf(constant.CannotReadResponseBodyMsg, err.Error())
		return nil, err
	}

	var data JsWikiGraphqlResponse
	err = json.Unmarshal(body, &data)
	if err != nil {
		s.Logger.Errorf(constant.CannotUnmarshallMsg, err.Error())
		return nil, err
	}
	return &data, nil
}

func (s *Syncer) getJsWikiUsersFromLdap() error {
	// Find all users in user group
	allUsersSearchRequest := goldap.NewSearchRequest(
		s.Ldap.LdapUsersBaseDN,
		goldap.ScopeSingleLevel, goldap.NeverDerefAliases, 0, 0, false,
		fmt.Sprintf(ldap.GroupActiveMembersFilter, goldap.EscapeFilter(s.UsersLdapGroup), goldap.EscapeFilter(s.Ldap.LdapGroupsBaseDN)),
		// In-order request attributes
		[]string{
			s.Ldap.LdapUsernameAttr,
			s.Ldap.LdapDisplayNameAttr,
		},
		nil,
	)

	sr, err := s.Ldap.Connection.Search(allUsersSearchRequest)
	if err != nil {
		s.Logger.Errorf(ldap.CannotSearchLdapUsersForGroupMsg,
			s.UsersLdapGroup, err.Error())
		return err
	}

	for _, en := range sr.Entries {
		username := en.GetAttributeValue(s.Ldap.LdapUsernameAttr)
		user := s.newUser()
		user.dn = en.DN
		user.displayName = en.GetAttributeValue(s.Ldap.LdapDisplayNameAttr)
		if len(username) > 0 {
			s.ldapAllUsers[username] = user
			s.Logger.Debugf("Created ldap user %s object %#v %#v", username, user, s.ldapAllUsers[username])
		}
	}

	// Find all expired users in users group
	expireDate := time.Now().AddDate(0, 0, -int(s.Ldap.LdapExpiredUsersDeltaDays)).Format("20060102150405")
	expiredUsersSearchRequest := goldap.NewSearchRequest(
		s.Ldap.LdapUsersBaseDN,
		goldap.ScopeSingleLevel, goldap.NeverDerefAliases, 0, 0, false,
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
		return err
	}

	for _, en := range sr.Entries {
		username := en.GetAttributeValue(s.Ldap.LdapUsernameAttr)
		if len(username) > 0 {
			s.ldapExpiredUsers[username] = true
			s.Logger.Debugf("Found expired password for ldap user %s", username)
		}
	}
	return nil
}

func (s *Syncer) getJsWikiGroupLdapMembers(gr string) (map[int]bool, bool) {
	isExist := false
	members := make(map[int]bool)
	groupname := gr
	if gr == "Administrators" {
		groupname = s.AdminLdapGroup
	} else {
		if !strings.HasPrefix(groupname, s.LdapGroupPrefix) {
			return members, isExist
		}
	}
	filter := fmt.Sprintf("(cn=%s)", goldap.EscapeFilter(groupname))

	// Find groups
	groupSearchRequest := goldap.NewSearchRequest(
		s.Ldap.LdapGroupsBaseDN,
		goldap.ScopeSingleLevel, goldap.NeverDerefAliases, 0, 0, false,
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

	if len(sr.Entries) == 0 {
		return members, isExist
	}

	isExist = true

	// Find members
	usersSearchRequest := goldap.NewSearchRequest(
		s.Ldap.LdapUsersBaseDN,
		goldap.ScopeSingleLevel, goldap.NeverDerefAliases, 0, 0, false,
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
		username := en.GetAttributeValue(s.Ldap.LdapUsernameAttr)
		if len(username) > 0 {
			if s.ldapAllUsers[username].id < 0 {
				s.Logger.Warningf("User %s can.t be added to group %s because it not exist in jswiki. User need to login before sync.", username, groupname)
				continue
			}
			members[s.ldapAllUsers[username].id] = true
		}
	}

	return members, isExist
}
