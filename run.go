package app

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"strconv"
	"syscall"

	"github.com/smxlong/kit/signalcontext"
	"github.com/smxlong/kit/webserver"
)

// Run the application
func (a *Application) Run() error {
	a.debugFlag, _ = strconv.ParseBool(os.Getenv("DEBUG"))
	setupFuncs := a.resourcesSetupFunctions()
	setupFuncs = append(setupFuncs, a.SetupFuncs...)
	r := &Resources{}
	for _, f := range setupFuncs {
		cleanup, err := f(r)
		if err != nil {
			return err
		}
		if cleanup != nil {
			defer func() {
				if err := cleanup(); err != nil {
					r.Logger.Errorw("cleanup error", "error", err)
				}
			}()
		}
	}
	ctx, cancel := signalcontext.WithSignals(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	return webserver.ListenAndServe(ctx, &http.Server{
		Addr:    ":8080",
		Handler: r.Gin,
	})
}

// Main is the entry point for the application.
func (a *Application) Main() {
	if err := a.Run(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
