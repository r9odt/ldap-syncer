package jswiki

const (
	// JsWikiGroupListQuery is graphql req
	JsWikiGroupListQuery string = "{ groups { list {id name isSystem }}}"
	// JsWikiGroupSingleQuery is graphql req
	JsWikiGroupSingleQuery string = "{ groups { single (id: %d) {id name isSystem permissions users {id} }}}"
	// JsWikiUserListQuery is graphql req
	JsWikiUserListQuery string = "{ users { list {id name isSystem isActive }}}"
	// JsWikiUserSingleQuery is graphql req
	JsWikiUserSingleQuery string = "{ users { single (id: %d) {id name isSystem isActive providerId timezone groups {id} }}}"

	// JsWikiAssignGroupQuery is graphql req
	JsWikiAssignGroupQuery string = "mutation { groups { assignUser (groupId: %d userId: %d) {responseResult {succeeded errorCode slug message}}}}"
	// JsWikiUnassignGroupQuery is graphql req
	JsWikiUnassignGroupQuery string = "mutation { groups { unassignUser (groupId: %d userId: %d) {responseResult {succeeded errorCode slug message}}}}"

	// JsWikiDeactivateUserQuery is graphql req
	JsWikiDeactivateUserQuery string = "mutation { users { deactivate (id: %d) {responseResult {succeeded errorCode slug message}}}}"
	// JsWikiActivateUserQuery is graphql req
	JsWikiActivateUserQuery string = "mutation { users { activate (id: %d) {responseResult {succeeded errorCode slug message}}}}"
	// JsWikiDeleteUserQuery is graphql req
	JsWikiDeleteUserQuery string = "mutation { users { delete (id: %d) {responseResult {succeeded errorCode slug message}}}}"
	// JsWikiUpdateUserQuery is graphql req
	JsWikiUpdateUserQuery string = `mutation { users { update (id: %d timezone: "%s") {responseResult {succeeded errorCode slug message}}}}`

	// UpdateTZFieldMsg is log msg for update timezone user field
	UpdateTZFieldMsg string = "Update timezone %s->%s"

	// UnassignGroupMsg is log msg for delete action
	UnassignGroupMsg string = "Unassigned from group"
	// AssignGroupMsg is log msg for delete action
	AssignGroupMsg string = "Assigned to group"
)
