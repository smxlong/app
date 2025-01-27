package app

// Application defines the application to run.
type Application struct {
	// Name of the application
	Name string
	// SetupFunc is a list of functions that will be called before the application starts.
	SetupFuncs []SetupFunc
	// debugFlag is true if the application is in debug mode
	debugFlag bool
}

// DebugMode returns true if the application is in debug mode.
func (a *Application) DebugMode() bool {
	return a.debugFlag
}
