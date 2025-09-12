package utils

import (
	"os"
	"strconv"
	"time"
)

func ParseBoolEnv(env string, defval bool) bool {
	var arg string
	if arg = os.Getenv(env); arg != "" {
		bval, err := strconv.ParseBool(arg)
		if err == nil {
			return bval
		}
	}
	return defval
}

func ParseStringEnv(env, defval string) string {
	var arg string
	if arg = os.Getenv(env); arg != "" {
		return arg
	}

	return defval
}

func ParseDurationEnv(env string, defval time.Duration) time.Duration {
	var arg string
	if arg = os.Getenv(env); arg != "" {
		val, err := time.ParseDuration(arg)
		if err == nil {
			return val
		}
	}

	return defval
}

func ParseUInt64Env(env string, defval uint64) uint64 {
	var arg string
	if arg = os.Getenv(env); arg != "" {
		val, err := strconv.ParseUint(arg, 10, 64)
		if err == nil {
			return val
		}
	}

	return defval
}

func ParseIntEnv(env string, defval int) int {
	var arg string
	if arg = os.Getenv(env); arg != "" {
		val, err := strconv.ParseInt(arg, 10, 64)
		if err == nil {
			return int(val)
		}
	}

	return defval
}

func AbsInt(x int) int {
	if x < 0 {
		return -x
	}
	return x
}
