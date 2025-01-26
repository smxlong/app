package app

import (
	"github.com/smxlong/kit/logger"
)

// setupLogger sets up the logger.
func (a *Application) setupLogger(r *Resources) (CleanupFunc, error) {
	var lopts []logger.Option
	if a.debugFlag {
		lopts = append(lopts, logger.WithLevel("DEBUG"))
	}
	l, err := logger.New(lopts...)
	if err != nil {
		return nil, err
	}
	r.Logger = l
	return func() error {
		l.SafeSync()
		return nil
	}, nil
}
