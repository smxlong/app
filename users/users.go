package users

import (
	"context"

	"github.com/smxlong/app/users/ent"
	"github.com/smxlong/app/users/ent/user"
	"golang.org/x/crypto/bcrypt"
)

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
	return &Users{cli: cli}, nil
}

// Close closes the database connection.
func (u *Users) Close() error {
	return u.cli.Close()
}

// Find returns the user with the given ID.
func (u *Users) Find(ctx context.Context, id string) (*ent.User, error) {
	return u.cli.User.Get(ctx, id)
}

// FindByEmail returns the user with the given email.
func (u *Users) FindByEmail(ctx context.Context, email string) (*ent.User, error) {
	return u.cli.User.Query().Where(user.Email(email)).Only(ctx)
}

// FindByName returns the user with the given name.
func (u *Users) FindByName(ctx context.Context, name string) (*ent.User, error) {
	return u.cli.User.Query().Where(user.Name(name)).Only(ctx)
}

// Create creates a new user with the given name and email.
func (u *Users) Create(ctx context.Context, name, email string) (*ent.User, error) {
	return u.cli.User.Create().SetName(name).SetEmail(email).Save(ctx)
}

// Login logs in the user using the password
func (u *Users) Login(ctx context.Context, user *ent.User, password string) (*ent.User, error) {
	if err := bcrypt.CompareHashAndPassword([]byte(user.PasswordHash), []byte(password)); err != nil {
		return nil, err
	}
	return user, nil
}

// LoginByEmail logs in the user using the email and password
func (u *Users) LoginByEmail(ctx context.Context, email, password string) (*ent.User, error) {
	user, err := u.FindByEmail(ctx, email)
	if err != nil {
		return nil, err
	}
	return u.Login(ctx, user, password)
}

// LoginByName logs in the user using the name and password
func (u *Users) LoginByName(ctx context.Context, name, password string) (*ent.User, error) {
	user, err := u.FindByName(ctx, name)
	if err != nil {
		return nil, err
	}
	return u.Login(ctx, user, password)
}

// Create creates a new user with the given name, email, and password.
func (u *Users) CreateWithPassword(ctx context.Context, name, email, password string) (*ent.User, error) {
	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return nil, err
	}
	return u.cli.User.Create().SetName(name).SetEmail(email).SetPasswordHash(string(hash)).Save(ctx)
}

// ChangePassword changes the password for the user.
func (u *Users) ChangePassword(ctx context.Context, user *ent.User, oldPassword, newPassword string) (*ent.User, error) {
	if err := bcrypt.CompareHashAndPassword([]byte(user.PasswordHash), []byte(oldPassword)); err != nil {
		return nil, err
	}
	hash, err := bcrypt.GenerateFromPassword([]byte(newPassword), bcrypt.DefaultCost)
	if err != nil {
		return nil, err
	}
	return user.Update().SetPasswordHash(string(hash)).Save(ctx)
}
