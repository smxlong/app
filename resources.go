package app

import (
	"github.com/gin-gonic/gin"
	"github.com/smxlong/app/token"
	"github.com/smxlong/app/users"
	"github.com/smxlong/kit/logger"
)

// Resources for the application to use. These are initialized in the order
// they are defined in the struct.
type Resources struct {
	Logger logger.Logger
	Users  *users.Users
	Issuer *token.Issuer
	Gin    *gin.Engine
}

// resourcesSetupFunctions returns the list of built-in setup functions to run.
// These should occur in an order matching the order of fields in the Resources
// struct.
func (a *Application) resourcesSetupFunctions() []SetupFunc {
	return []SetupFunc{
		a.setupLogger,          // sets up resources.Logger
		a.setupUsers,           // sets up resources.Users
		a.setupUserTokenIssuer, // sets up resources.Issuer
		a.setupGin,             // sets up resources.Gin
		a.setupUsersAPI,        // sets up resources.Gin /api/users endpoints
	}
}
