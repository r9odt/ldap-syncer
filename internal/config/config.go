package config

import (
	"context"

	"github.com/r9odt/ldap-syncer/internal/client/ldap"
	"github.com/r9odt/ldap-syncer/internal/constant"
	"github.com/r9odt/ldap-syncer/internal/logging"
	"github.com/r9odt/ldap-syncer/internal/sync/gitlab"
	"github.com/r9odt/ldap-syncer/internal/sync/jswiki"
	"github.com/r9odt/ldap-syncer/internal/utils"
)

type Config struct {
	Ldap   *ldap.Config
	Gitlab *gitlab.Syncer
	JsWiki *jswiki.Syncer

	Logger logging.Logger
	Ctx    context.Context
}

func New(ctx context.Context) (*Config, error) {
	var (
		c = &Config{
			Ctx: ctx,
		}
	)

	logger, err := logging.ConfigureLog(utils.ParseStringEnv(constant.LogFileEnv, "stdout"), utils.ParseStringEnv(constant.LogLevelEnv, "info"), "syncer", !utils.ParseBoolEnv(constant.LogJSONEnv, false))
	if err != nil {
		return nil, err
	}
	c.Logger = logger

	l, lerr := ldap.New(ctx)
	g, gerr := gitlab.New(ctx, l)
	j, jerr := jswiki.New(ctx, l)

	if lerr != nil || gerr != nil || jerr != nil {
		return c, constant.ErrValidate
	}

	c.Ldap = l
	c.Gitlab = g
	c.JsWiki = j
	logger.Debugf("%#v", c)
	logger.Debugf("%#v", l)
	logger.Debugf("%#v", g)

	return c, nil
}
