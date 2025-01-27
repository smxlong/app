package app

// SetupFunc runs before the application starts to set up a resource.
type SetupFunc func(*Resources) (CleanupFunc, error)

// CleanupFunc runs after the application stops to clean up a resource.
type CleanupFunc func() error

// setupFunctions returns the list of setup functions to run.
func (a *Application) setupFunctions() []SetupFunc {
	return []SetupFunc{
		a.setupLogger,
		a.setupUsers,
		a.setupUserTokenIssuer,
		a.setupGin,
		a.setupUsersAPI,
	}
}
