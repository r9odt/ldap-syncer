package main

import (
	"context"
	"fmt"
	"log"
	"os"
	"os/signal"
	"sync"
	"syscall"

	"github.com/r9odt/ldap-syncer/internal/config"
)

func main() {
	var (
		err error
		wg  sync.WaitGroup
	)
	ctx, cancel := context.WithCancel(context.Background())

	config, err := config.New(ctx)
	if err != nil {
		if config.Logger != nil {
			config.Logger.Fatalf("Cannot configure syncer: %s", err.Error())
		} else {
			log.Fatalf("Cannot configure syncer: %s", err.Error())
		}
	}

	ch := make(chan os.Signal, 1)
	signal.Notify(ch, syscall.SIGINT, syscall.SIGTERM)

	// run gitlab sync
	wg.Go(config.Gitlab.Sync)
	// run jswiki sync
	wg.Go(config.JsWiki.Sync)

	config.Logger.Info(fmt.Sprint(<-ch))

	// cancel context
	cancel()
	// wait all goroutines
	wg.Wait()
}
