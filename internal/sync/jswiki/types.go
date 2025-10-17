package jswiki

type User struct {
	dn          string
	id          int
	displayName string
}

func (s *Syncer) newUser() *User {
	return &User{
		dn:          "",
		id:          -1,
		displayName: "",
	}
}

type JsWikiGroupMinimal struct {
	Id       int    `json:"id"`
	Name     string `json:"name"`
	IsSystem bool   `json:"isSystem"`
}

type JsWikiGroup struct {
	JsWikiGroupMinimal
	Permissions []string            `json:"permissions"`
	Users       []JsWikiUserMinimal `json:"users"`

	usersMap map[int]bool
}

func newJsWikiGroupFromMinimal(g JsWikiGroupMinimal) *JsWikiGroup {
	return &JsWikiGroup{JsWikiGroupMinimal: g}
}

type JsWikiUserMinimal struct {
	Id       int    `json:"id"`
	Name     string `json:"name"`
	IsSystem bool   `json:"isSystem"`
	IsActive bool   `json:"isActive"`
}

type JsWikiUser struct {
	JsWikiUserMinimal
	ProviderId string               `json:"providerId"`
	Timezone   string               `json:"timezone"`
	Groups     []JsWikiGroupMinimal `json:"groups"`
}
