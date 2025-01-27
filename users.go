package app

import (
	"fmt"
	"os"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/lestrrat-go/jwx/v3/jwt"
	_ "github.com/mattn/go-sqlite3"

	users_api "github.com/smxlong/app/api/users"
	"github.com/smxlong/app/token"
	"github.com/smxlong/app/users"
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
	// POST /api/users/signup
	r.Gin.POST("/api/users/signup",
		Endpoint(r, func(c *gin.Context, r *Resources, request *users_api.SignupRequest) (*users_api.SignupResponse, error) {
			ctx := c.Request.Context()
			_, err := r.Users.Create(ctx, request.Name, request.Email, request.Password)
			if err != nil {
				return nil, err
			}
			return &users_api.SignupResponse{
				MessageResponse: users_api.MessageResponse{
					Message: "user created",
				},
			}, nil
		}))
	// POST /api/users/login
	r.Gin.POST("/api/users/login",
		Endpoint(r, func(c *gin.Context, r *Resources, request *users_api.LoginRequest) (*users_api.LoginResponse, error) {
			ctx := c.Request.Context()
			var user *users.User
			var err error
			if user, err = r.Users.FindByEmail(ctx, request.NameOrEmail); err != nil {
				if user, err = r.Users.FindByName(ctx, request.NameOrEmail); err != nil {
					return nil, err
				}
			}
			user, err = r.Users.Login(ctx, user, request.Password)
			if err != nil {
				return nil, err
			}
			token, err := r.Issuer.Issue(user.ID)
			if err != nil {
				return nil, err
			}
			return &users_api.LoginResponse{
				Token: string(token),
			}, nil
		}))
	// POST /api/users/change-password
	r.Gin.POST("/api/users/change-password",
		r.Issuer.Middleware(),
		r.Users.Middleware(),
		Endpoint(r, func(c *gin.Context, r *Resources, request *users_api.ChangePasswordRequest) (*users_api.ChangePasswordResponse, error) {
			ctx := c.Request.Context()
			user := c.MustGet("user").(*users.User)
			_, err := r.Users.ChangePassword(ctx, user, request.OldPassword, request.NewPassword)
			if err != nil {
				return nil, err
			}
			return &users_api.ChangePasswordResponse{
				MessageResponse: users_api.MessageResponse{
					Message: "password changed",
				},
			}, nil
		}))
	// POST /api/users/request-reset-password
	r.Gin.POST("/api/users/request-reset-password",
		Endpoint(r, func(c *gin.Context, r *Resources, request *users_api.RequestResetPasswordRequest) (*users_api.RequestResetPasswordResponse, error) {
			ctx := c.Request.Context()
			user, err := r.Users.FindByEmail(ctx, request.Email)
			if err != nil {
				return nil, err
			}
			jwt, err := r.Issuer.Issue(user.ID, "password_reset_before", time.Now().Add(3*24*time.Hour).Format(time.RFC3339))
			if err != nil {
				return nil, err
			}
			if err := r.Users.RegisterResetPasswordToken(ctx, user, string(jwt)); err != nil {
				return nil, err
			}
			r.Logger.Infow("reset password token created", "token", string(jwt))
			return &users_api.RequestResetPasswordResponse{
				MessageResponse: users_api.MessageResponse{
					Message: "email sent",
				},
			}, nil
		}))
	// POST /api/users/reset-password
	r.Gin.POST("/api/users/reset-password",
		r.Issuer.Middleware(),
		r.Users.Middleware(),
		Endpoint(r, func(c *gin.Context, r *Resources, request *users_api.ResetPasswordRequest) (*users_api.ResetPasswordResponse, error) {
			ctx := c.Request.Context()
			jwtstr := c.MustGet("jwt").(string)
			user := c.MustGet("user").(*users.User)
			claims := c.MustGet("claims").(jwt.Token)
			var prb string
			if err := claims.Get("password_reset_before", &prb); err != nil {
				return nil, err
			}
			passwordResetBefore, err := time.Parse(time.RFC3339, prb)
			if err != nil {
				return nil, err
			}
			if time.Now().After(passwordResetBefore) {
				return nil, fmt.Errorf("token expired")
			}
			if err := r.Users.VerifyResetPasswordToken(ctx, user, jwtstr); err != nil {
				return nil, err
			}
			_, err = r.Users.ResetPassword(ctx, user, request.NewPassword)
			if err != nil {
				return nil, err
			}
			return &users_api.ResetPasswordResponse{
				MessageResponse: users_api.MessageResponse{
					Message: "password reset",
				},
			}, nil
		}))
	// POST /api/users/delete
	r.Gin.POST("/api/users/delete",
		r.Issuer.Middleware(),
		r.Users.Middleware(),
		Endpoint(r, func(c *gin.Context, r *Resources, request *users_api.DeleteRequest) (*users_api.DeleteResponse, error) {
			ctx := c.Request.Context()
			user := c.MustGet("user").(*users.User)
			err := r.Users.Delete(ctx, user, request.Password)
			if err != nil {
				return nil, err
			}
			return &users_api.DeleteResponse{
				MessageResponse: users_api.MessageResponse{
					Message: "user deleted",
				},
			}, nil
		}))
	return nil, nil
}
