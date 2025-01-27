package users

import (
	"context"
	"errors"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/lestrrat-go/jwx/v3/jwt"
	"github.com/smxlong/app/api"
	"github.com/smxlong/app/users/ent"
	"github.com/smxlong/app/users/ent/token"
	"github.com/smxlong/app/users/ent/user"
	"golang.org/x/crypto/bcrypt"
)

// User is a user of the system.
type User = ent.User

// Users implements the user management system.
type Users struct {
	cli *ent.Client
}

// New creates a new Users, using the given data source driver and data source name
// to connect to the database.
func New(driver, dsn string) (*Users, error) {
	cli, err := ent.Open(driver, dsn)
	if err != nil {
		return nil, err
	}
	if err := cli.Schema.Create(context.Background()); err != nil {
		return nil, err
	}
	return &Users{cli: cli}, nil
}

// Close closes the database connection.
func (u *Users) Close() error {
	return u.cli.Close()
}

// Find returns the user with the given ID.
func (u *Users) Find(ctx context.Context, id string) (*User, error) {
	return u.cli.User.Get(ctx, id)
}

// FindByEmail returns the user with the given email.
func (u *Users) FindByEmail(ctx context.Context, email string) (*User, error) {
	user, err := u.cli.User.Query().
		Where(user.Email(email)).Only(ctx)
	if ent.IsNotFound(err) {
		return nil, api.ErrUnauthorized
	}
	return user, err
}

// FindByName returns the user with the given name.
func (u *Users) FindByName(ctx context.Context, name string) (*User, error) {
	user, err := u.cli.User.Query().
		Where(user.Name(name)).Only(ctx)
	if ent.IsNotFound(err) {
		return nil, api.ErrUnauthorized
	}
	return user, err
}

// Create creates a new user with the given name, email, and password.
func (u *Users) Create(ctx context.Context, name, email, password string) (*User, error) {
	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return nil, err
	}
	user, err := u.cli.User.Create().
		SetName(name).
		SetEmail(email).
		SetPasswordHash(string(hash)).
		Save(ctx)
	if err != nil {
		if ent.IsConstraintError(err) {
			return nil, api.ErrConflict.WithMessage("user already exists")
		}
		return nil, err
	}
	return user, nil
}

// Login logs in the user using the password
func (u *Users) Login(ctx context.Context, user *User, password string) (*User, error) {
	if err := bcrypt.CompareHashAndPassword([]byte(user.PasswordHash), []byte(password)); err != nil {
		return nil, api.ErrUnauthorized
	}
	return user, nil
}

// LoginByEmail logs in the user using the email and password
func (u *Users) LoginByEmail(ctx context.Context, email, password string) (*User, error) {
	user, err := u.FindByEmail(ctx, email)
	if err != nil {
		if ent.IsNotFound(err) {
			return nil, api.ErrUnauthorized
		}
		return nil, err
	}
	return u.Login(ctx, user, password)
}

// LoginByName logs in the user using the name and password
func (u *Users) LoginByName(ctx context.Context, name, password string) (*User, error) {
	user, err := u.FindByName(ctx, name)
	if err != nil {
		if ent.IsNotFound(err) {
			return nil, api.ErrUnauthorized
		}
		return nil, err
	}
	return u.Login(ctx, user, password)
}

// ChangePassword changes the password for the user.
func (u *Users) ChangePassword(ctx context.Context, user *User, oldPassword, newPassword string) (*User, error) {
	if err := bcrypt.CompareHashAndPassword([]byte(user.PasswordHash), []byte(oldPassword)); err != nil {
		return nil, api.ErrUnauthorized
	}
	hash, err := bcrypt.GenerateFromPassword([]byte(newPassword), bcrypt.DefaultCost)
	if err != nil {
		if errors.Is(err, bcrypt.ErrPasswordTooLong) {
			return nil, api.ErrBadRequest.WithMessage("password too long")
		}
		return nil, err
	}
	return user.Update().
		SetPasswordHash(string(hash)).
		Save(ctx)
}

// RegisterResetPasswordToken registers the reset password token for the user.
func (u *Users) RegisterResetPasswordToken(ctx context.Context, user *User, jwtstr string) error {
	// Parse the token and get the password_reset_before claim so we can set the token's expiration time field.
	parsed, err := jwt.Parse([]byte(jwtstr), jwt.WithValidate(false), jwt.WithVerify(false))
	if err != nil {
		return err
	}
	var passwordResetBefore string
	if err := parsed.Get("password_reset_before", &passwordResetBefore); err != nil {
		return api.ErrInternalServerError.WithMessage("could not get password_reset_before claim")
	}
	passwordResetBeforeTime, err := time.Parse(time.RFC3339, passwordResetBefore)
	if err != nil {
		return api.ErrInternalServerError.WithMessage("could not parse password_reset_before claim")
	}
	return u.cli.Token.Create().
		SetUser(user).
		SetToken(jwtstr).
		SetType("reset_password").
		SetExpiresAt(passwordResetBeforeTime).
		Exec(ctx)
}

// VerifyResetPasswordToken verifies the reset password token for the user. It
// then deletes the token.
func (u *Users) VerifyResetPasswordToken(ctx context.Context, us *User, jwt string) error {
	t, err := u.cli.Token.Query().Where(
		token.HasUserWith(user.ID(us.ID)),
		token.TokenEQ(jwt),
		token.TypeEQ("reset_password"),
		token.ExpiresAtGT(time.Now()),
	).Only(ctx)
	if err != nil {
		if ent.IsNotFound(err) {
			return api.ErrUnauthorized.WithMessage("invalid reset password token")
		}
		return err
	}
	if err := u.cli.Token.DeleteOne(t).Exec(ctx); err != nil {
		return err
	}
	return nil
}

// PruneResetPasswordTokens prunes the expired reset password tokens.
func (u *Users) PruneResetPasswordTokens(ctx context.Context) error {
	_, err := u.cli.Token.Delete().
		Where(
			token.TypeEQ("reset_password"),
			token.ExpiresAtLT(time.Now()),
		).
		Exec(ctx)
	return err
}

// ResetPassword resets the password for the user.
func (u *Users) ResetPassword(ctx context.Context, user *User, newPassword string) (*User, error) {
	hash, err := bcrypt.GenerateFromPassword([]byte(newPassword), bcrypt.DefaultCost)
	if err != nil {
		if errors.Is(err, bcrypt.ErrPasswordTooLong) {
			return nil, api.ErrBadRequest.WithMessage("password too long")
		}
		return nil, err
	}
	return user.Update().SetPasswordHash(string(hash)).Save(ctx)
}

// Delete deletes the user.
func (u *Users) Delete(ctx context.Context, user *User, password string) error {
	if err := bcrypt.CompareHashAndPassword([]byte(user.PasswordHash), []byte(password)); err != nil {
		return err
	}
	return u.cli.User.DeleteOne(user).Exec(ctx)
}

// Middleware returns a middleware that sets the user in the context based on
// the subject in the JWT.
func (u *Users) Middleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		ctx := c.Request.Context()
		sub, ok := c.Get("subject")
		if !ok {
			c.AbortWithStatus(http.StatusUnauthorized)
			return
		}
		user, err := u.Find(ctx, sub.(string))
		if err != nil {
			c.AbortWithStatus(http.StatusUnauthorized)
			return
		}
		c.Set("user", user)
		c.Next()
	}
}
