package jswiki

type JsWikiGraphqlResponse struct {
	Data JsWikiGraphqlResponseData `json:"data"`
}

type JsWikiGraphqlResponseData struct {
	Groups JsWikiGraphqlResponseGroups `json:"groups"`
	Users  JsWikiGraphqlResponseUsers  `json:"users"`
}

type JsWikiGraphqlResponseUsers struct {
	Single     JsWikiUser          `json:"single"`
	List       []JsWikiUserMinimal `json:"list"`
	Activate   JsWikiActivate      `json:"activate"`
	Deactivate JsWikiDectivate     `json:"deactivate"`
	Delete     JsWikiDelete        `json:"delete"`
}

type JsWikiActivate struct {
	ResponseResult JsWikiResponseResult `json:"responseResult"`
}

type JsWikiDectivate struct {
	ResponseResult JsWikiResponseResult `json:"responseResult"`
}

type JsWikiDelete struct {
	ResponseResult JsWikiResponseResult `json:"responseResult"`
}

type JsWikiGraphqlResponseGroups struct {
	Single JsWikiGroup          `json:"single"`
	List   []JsWikiGroupMinimal `json:"list"`
}

type JsWikiResponseResult struct {
	Succeeded bool   `json:"succeeded"`
	ErrorCode int    `json:"errorCode"`
	Slug      string `json:"slug"`
	Message   string `json:"message"`
}
