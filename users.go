package app

import (
	"fmt"
	"os"
	"time"

	_ "github.com/mattn/go-sqlite3"

	"github.com/smxlong/app/token"
	"github.com/smxlong/app/users"
	users_web "github.com/smxlong/app/web/users"
)

// setupUsers sets up the users database
func (a *Application) setupUsers(r *Resources) (CleanupFunc, error) {
	driver := os.Getenv("USERS_DATABASE_DRIVER")
	if driver == "" {
		driver = "sqlite3"
	}
	dsn := os.Getenv("USERS_DATABASE_DATA_SOURCE_NAME")
	if dsn == "" {
		// in memory, fk=1
		dsn = ":memory:?_fk=1"
	}
	db, err := users.New(driver, dsn)
	if err != nil {
		return nil, err
	}
	r.Users = db
	return func() error {
		return db.Close()
	}, nil
}

// setupUserTokenIssuer sets up the user token issuer
func (a *Application) setupUserTokenIssuer(r *Resources) (CleanupFunc, error) {
	secret := os.Getenv("USER_TOKEN_SECRET")
	if secret == "" {
		return nil, fmt.Errorf("USER_TOKEN_SECRET is required")
	}
	issuer := os.Getenv("USER_TOKEN_ISSUER")
	if issuer == "" {
		issuer = "app"
	}
	audience := os.Getenv("USER_TOKEN_AUDIENCE")
	if audience == "" {
		audience = "app"
	}
	r.Issuer = &token.Issuer{
		Issuer:   issuer,
		Audience: audience,
		ValidFor: 24 * time.Hour,
		Secret:   []byte(secret),
	}
	return nil, nil
}

// setupUsersAPI sets up the users API endpoints
func (a *Application) setupUsersAPI(r *Resources) (CleanupFunc, error) {
	r.Gin.POST("/api/users/signup", users_web.Signup(r.Users))
	r.Gin.POST("/api/users/login", users_web.Login(r.Issuer, r.Users))
	r.Gin.POST("/api/users/change-password", r.Issuer.Middleware(), r.Users.Middleware(), users_web.ChangePassword(r.Users))
	r.Gin.POST("/api/users/request-reset-password", users_web.RequestResetPassword(r.Logger, r.Issuer, r.Users))
	r.Gin.POST("/api/users/reset-password", r.Issuer.Middleware(), r.Users.Middleware(), users_web.ResetPassword(r.Logger, r.Issuer, r.Users))
	r.Gin.POST("/api/users/delete", r.Issuer.Middleware(), r.Users.Middleware(), users_web.Delete(r.Users))
	return nil, nil
}
