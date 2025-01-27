package app

import (
	"github.com/gin-gonic/gin"
	"github.com/smxlong/app/token"
	"github.com/smxlong/app/users"
	"github.com/smxlong/kit/logger"
)

// Application defines the application to run.
type Application struct {
	// Name of the application
	Name string
	// SetupFunc is a list of functions that will be called before the application starts.
	SetupFuncs []SetupFunc
	// debugFlag is true if the application is in debug mode
	debugFlag bool
}

// Resources for the application to use.
type Resources struct {
	Logger logger.Logger
	Gin    *gin.Engine
	Users  *users.Users
	Issuer *token.Issuer
}

// DebugMode returns true if the application is in debug mode.
func (a *Application) DebugMode() bool {
	return a.debugFlag
}
