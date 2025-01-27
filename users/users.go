package users

import (
	"context"
	"errors"
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/smxlong/app/users/ent"
	"github.com/smxlong/app/users/ent/token"
	"github.com/smxlong/app/users/ent/user"
	"golang.org/x/crypto/bcrypt"
)

var ErrInvalidToken = errors.New("invalid token")

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
	return u.cli.User.Query().Where(user.Email(email)).Only(ctx)
}

// FindByName returns the user with the given name.
func (u *Users) FindByName(ctx context.Context, name string) (*User, error) {
	return u.cli.User.Query().Where(user.Name(name)).Only(ctx)
}

// Create creates a new user with the given name, email, and password.
func (u *Users) Create(ctx context.Context, name, email, password string) (*User, error) {
	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return nil, err
	}
	return u.cli.User.Create().SetName(name).SetEmail(email).SetPasswordHash(string(hash)).Save(ctx)
}

// Login logs in the user using the password
func (u *Users) Login(ctx context.Context, user *User, password string) (*User, error) {
	if err := bcrypt.CompareHashAndPassword([]byte(user.PasswordHash), []byte(password)); err != nil {
		return nil, err
	}
	return user, nil
}

// LoginByEmail logs in the user using the email and password
func (u *Users) LoginByEmail(ctx context.Context, email, password string) (*User, error) {
	user, err := u.FindByEmail(ctx, email)
	if err != nil {
		return nil, err
	}
	return u.Login(ctx, user, password)
}

// LoginByName logs in the user using the name and password
func (u *Users) LoginByName(ctx context.Context, name, password string) (*User, error) {
	user, err := u.FindByName(ctx, name)
	if err != nil {
		return nil, err
	}
	return u.Login(ctx, user, password)
}

// ChangePassword changes the password for the user.
func (u *Users) ChangePassword(ctx context.Context, user *User, oldPassword, newPassword string) (*User, error) {
	if err := bcrypt.CompareHashAndPassword([]byte(user.PasswordHash), []byte(oldPassword)); err != nil {
		return nil, err
	}
	hash, err := bcrypt.GenerateFromPassword([]byte(newPassword), bcrypt.DefaultCost)
	if err != nil {
		return nil, err
	}
	return user.Update().SetPasswordHash(string(hash)).Save(ctx)
}

// RegisterResetPasswordToken registers the reset password token for the user.
func (u *Users) RegisterResetPasswordToken(ctx context.Context, user *User, jwt string) error {
	_, err := u.cli.Token.Create().
		SetUser(user).
		SetToken(jwt).
		SetType("reset_password").
		Save(ctx)
	return err
}

// VerifyResetPasswordToken verifies the reset password token for the user. It
// then deletes the token.
func (u *Users) VerifyResetPasswordToken(ctx context.Context, us *User, jwt string) error {
	t, err := u.cli.Token.Query().Where(
		token.HasUserWith(user.ID(us.ID)),
		token.TokenEQ(jwt),
		token.TypeEQ("reset_password"),
	).Only(ctx)
	if err != nil {
		return ErrInvalidToken
	}
	if err := u.cli.Token.DeleteOne(t).Exec(ctx); err != nil {
		return err
	}
	return nil
}

// ResetPassword resets the password for the user.
func (u *Users) ResetPassword(ctx context.Context, user *User, newPassword string) (*User, error) {
	hash, err := bcrypt.GenerateFromPassword([]byte(newPassword), bcrypt.DefaultCost)
	if err != nil {
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
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "missing subject in context"})
			return
		}
		user, err := u.Find(ctx, sub.(string))
		if err != nil {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "invalid subject"})
			return
		}
		c.Set("user", user)
		c.Next()
	}
}
