package types

type GraphqlQuery struct {
	Query string `json:"query"`
}

func NewGraphqlQuery(q string) *GraphqlQuery {
	return &GraphqlQuery{
		Query: q,
	}
}
