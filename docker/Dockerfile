FROM --platform=${BUILDPLATFORM:-linux/amd64} golang:1.25.1 AS build

ENV GO_SRC=/usr/local/go/src
WORKDIR ${GO_SRC}/github.com/r9odt/ldap-syncer
COPY . .

RUN go get ./... && go mod vendor

RUN CGO_ENABLED=0 GOOS=${TARGETOS:-linux} GOARCH=${TARGETARCH:-amd64} go build \
	-a -installsuffix cgo \
	-o /syncer cmd/main.go; 	

FROM scratch AS runtime

COPY --from=build /syncer /

ENTRYPOINT [ "/syncer" ]
