package users

import (
	"context"
	"testing"
	"time"

	_ "github.com/mattn/go-sqlite3"
	"github.com/smxlong/app/api"
	"github.com/smxlong/app/token"
	uent_token "github.com/smxlong/app/users/ent/token"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/bcrypt"
)

type typeUser struct {
	Name     string
	Email    string
	Password string
}

var testUsers = []typeUser{
	{"test1", "test1@example.com", "password1"},
	{"test2", "test2@example.com", "password2"},
}

func Test_that_New_returns_a_new_Users(t *testing.T) {
	u, err := New("sqlite3", ":memory:?_fk=1")
	require.NoError(t, err)
	require.NotNil(t, u)
	require.NoError(t, u.Close())
}

// newUsers is a helper that creates a new Users for testing.
func newUsers(t *testing.T) *Users {
	u, err := New("sqlite3", ":memory:?_fk=1")
	require.NoError(t, err)
	t.Cleanup(func() {
		require.NoError(t, u.Close())
	})
	return u
}

// testContext returns a new context for testing. It times out after 5 seconds.
func testContext(t *testing.T) context.Context {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	t.Cleanup(cancel)
	return ctx
}

// testIssuer returns a new token.Issuer for testing.
func testIssuer(t *testing.T) *token.Issuer {
	return &token.Issuer{
		Issuer:   "test",
		Audience: "test",
		ValidFor: 24 * time.Hour,
		Secret:   []byte("secret"),
	}
}

func Test_that_Create_creates_a_new_user(t *testing.T) {
	u := newUsers(t)
	ctx := testContext(t)
	user, err := u.Create(ctx, testUsers[0].Name, testUsers[0].Email, testUsers[0].Password)
	require.NoError(t, err)
	require.NotNil(t, user)
	require.Equal(t, testUsers[0].Name, user.Name)
	require.Equal(t, testUsers[0].Email, user.Email)
	require.NoError(t, bcrypt.CompareHashAndPassword([]byte(user.PasswordHash), []byte(testUsers[0].Password)))
}

func Test_that_Create_fails_when_the_email_is_already_registered(t *testing.T) {
	u := newUsers(t)
	ctx := testContext(t)
	_, err := u.Create(ctx, testUsers[0].Name, testUsers[0].Email, testUsers[0].Password)
	require.NoError(t, err)
	_, err = u.Create(ctx, testUsers[1].Name, testUsers[0].Email, testUsers[1].Password)
	require.ErrorIs(t, err, api.ErrConflict)
}

func Test_that_Create_fails_when_the_name_is_already_registered(t *testing.T) {
	u := newUsers(t)
	ctx := testContext(t)
	_, err := u.Create(ctx, testUsers[0].Name, testUsers[0].Email, testUsers[0].Password)
	require.NoError(t, err)
	_, err = u.Create(ctx, testUsers[0].Name, testUsers[1].Email, testUsers[1].Password)
	require.ErrorIs(t, err, api.ErrConflict)
}

func Test_that_Find_returns_the_user_with_the_given_ID(t *testing.T) {
	u := newUsers(t)
	ctx := testContext(t)
	user, err := u.Create(ctx, testUsers[0].Name, testUsers[0].Email, testUsers[0].Password)
	require.NoError(t, err)
	require.NotNil(t, user)
	found, err := u.Find(ctx, user.ID)
	require.NoError(t, err)
	require.NotNil(t, found)
	require.Equal(t, user.ID, found.ID)
	require.Equal(t, user.Name, found.Name)
	require.Equal(t, user.Email, found.Email)
	require.Equal(t, user.PasswordHash, found.PasswordHash)
}

func Test_that_Find_returns_error_when_the_user_is_not_found(t *testing.T) {
	u := newUsers(t)
	ctx := testContext(t)
	_, err := u.Find(ctx, "nonexistent")
	require.ErrorIs(t, err, api.ErrNotFound)
}

func Test_that_FindByEmail_returns_the_user_with_the_given_email(t *testing.T) {
	u := newUsers(t)
	ctx := testContext(t)
	user, err := u.Create(ctx, testUsers[0].Name, testUsers[0].Email, testUsers[0].Password)
	require.NoError(t, err)
	require.NotNil(t, user)
	found, err := u.FindByEmail(ctx, user.Email)
	require.NoError(t, err)
	require.NotNil(t, found)
	require.Equal(t, user.ID, found.ID)
	require.Equal(t, user.Name, found.Name)
	require.Equal(t, user.Email, found.Email)
	require.Equal(t, user.PasswordHash, found.PasswordHash)
}

func Test_that_FindByEmail_returns_error_when_the_user_is_not_found(t *testing.T) {
	u := newUsers(t)
	ctx := testContext(t)
	_, err := u.FindByEmail(ctx, "nonexistent")
	require.ErrorIs(t, err, api.ErrNotFound)
}

func Test_that_FindByName_returns_the_user_with_the_given_name(t *testing.T) {
	u := newUsers(t)
	ctx := testContext(t)
	user, err := u.Create(ctx, testUsers[0].Name, testUsers[0].Email, testUsers[0].Password)
	require.NoError(t, err)
	require.NotNil(t, user)
	found, err := u.FindByName(ctx, user.Name)
	require.NoError(t, err)
	require.NotNil(t, found)
	require.Equal(t, user.ID, found.ID)
	require.Equal(t, user.Name, found.Name)
	require.Equal(t, user.Email, found.Email)
	require.Equal(t, user.PasswordHash, found.PasswordHash)
}

func Test_that_FindByName_returns_error_when_the_user_is_not_found(t *testing.T) {
	u := newUsers(t)
	ctx := testContext(t)
	_, err := u.FindByName(ctx, "nonexistent")
	require.ErrorIs(t, err, api.ErrNotFound)
}

func Test_that_Login_logs_in_the_user(t *testing.T) {
	u := newUsers(t)
	ctx := testContext(t)
	user, err := u.Create(ctx, testUsers[0].Name, testUsers[0].Email, testUsers[0].Password)
	require.NoError(t, err)
	require.NotNil(t, user)
	loggedIn, err := u.Login(ctx, user, testUsers[0].Password)
	require.NoError(t, err)
	require.NotNil(t, loggedIn)
	require.Equal(t, user.ID, loggedIn.ID)
	require.Equal(t, user.Name, loggedIn.Name)
	require.Equal(t, user.Email, loggedIn.Email)
	require.Equal(t, user.PasswordHash, loggedIn.PasswordHash)
}

func Test_that_Login_fails_when_the_password_is_incorrect(t *testing.T) {
	u := newUsers(t)
	ctx := testContext(t)
	user, err := u.Create(ctx, testUsers[0].Name, testUsers[0].Email, testUsers[0].Password)
	require.NoError(t, err)
	require.NotNil(t, user)
	_, err = u.Login(ctx, user, "incorrect")
	require.ErrorIs(t, err, api.ErrUnauthorized)
}

func Test_that_Login_fails_when_the_user_is_not_found(t *testing.T) {
	u := newUsers(t)
	ctx := testContext(t)
	_, err := u.Login(ctx, &User{ID: "nonexistent"}, "password")
	require.ErrorIs(t, err, api.ErrUnauthorized)
}

func Test_that_LoginByEmail_logs_in_the_user(t *testing.T) {
	u := newUsers(t)
	ctx := testContext(t)
	user, err := u.Create(ctx, testUsers[0].Name, testUsers[0].Email, testUsers[0].Password)
	require.NoError(t, err)
	require.NotNil(t, user)
	loggedIn, err := u.LoginByEmail(ctx, testUsers[0].Email, testUsers[0].Password)
	require.NoError(t, err)
	require.NotNil(t, loggedIn)
	require.Equal(t, user.ID, loggedIn.ID)
	require.Equal(t, user.Name, loggedIn.Name)
	require.Equal(t, user.Email, loggedIn.Email)
	require.Equal(t, user.PasswordHash, loggedIn.PasswordHash)
}

func Test_that_LoginByEmail_fails_when_the_password_is_incorrect(t *testing.T) {
	u := newUsers(t)
	ctx := testContext(t)
	user, err := u.Create(ctx, testUsers[0].Name, testUsers[0].Email, testUsers[0].Password)
	require.NoError(t, err)
	require.NotNil(t, user)
	_, err = u.LoginByEmail(ctx, testUsers[0].Email, "incorrect")
	require.ErrorIs(t, err, api.ErrUnauthorized)
}

func Test_that_LoginByEmail_fails_when_the_user_is_not_found(t *testing.T) {
	u := newUsers(t)
	ctx := testContext(t)
	_, err := u.LoginByEmail(ctx, "nonexistent", "password")
	require.ErrorIs(t, err, api.ErrUnauthorized)
}

func Test_that_LoginByName_logs_in_the_user(t *testing.T) {
	u := newUsers(t)
	ctx := testContext(t)
	user, err := u.Create(ctx, testUsers[0].Name, testUsers[0].Email, testUsers[0].Password)
	require.NoError(t, err)
	require.NotNil(t, user)
	loggedIn, err := u.LoginByName(ctx, testUsers[0].Name, testUsers[0].Password)
	require.NoError(t, err)
	require.NotNil(t, loggedIn)
	require.Equal(t, user.ID, loggedIn.ID)
	require.Equal(t, user.Name, loggedIn.Name)
	require.Equal(t, user.Email, loggedIn.Email)
	require.Equal(t, user.PasswordHash, loggedIn.PasswordHash)
}

func Test_that_LoginByName_fails_when_the_password_is_incorrect(t *testing.T) {
	u := newUsers(t)
	ctx := testContext(t)
	user, err := u.Create(ctx, testUsers[0].Name, testUsers[0].Email, testUsers[0].Password)
	require.NoError(t, err)
	require.NotNil(t, user)
	_, err = u.LoginByName(ctx, testUsers[0].Name, "incorrect")
	require.ErrorIs(t, err, api.ErrUnauthorized)
}

func Test_that_LoginByName_fails_when_the_user_is_not_found(t *testing.T) {
	u := newUsers(t)
	ctx := testContext(t)
	_, err := u.LoginByName(ctx, "nonexistent", "password")
	require.ErrorIs(t, err, api.ErrUnauthorized)
}

func Test_that_ChangePassword_changes_the_password(t *testing.T) {
	u := newUsers(t)
	ctx := testContext(t)
	user, err := u.Create(ctx, testUsers[0].Name, testUsers[0].Email, testUsers[0].Password)
	require.NoError(t, err)
	require.NotNil(t, user)
	changedUser, err := u.ChangePassword(ctx, user, testUsers[0].Password, "newpassword")
	require.NoError(t, err)
	require.NotNil(t, changedUser)
	require.Equal(t, user.ID, changedUser.ID)
	require.Equal(t, user.Name, changedUser.Name)
	require.Equal(t, user.Email, changedUser.Email)
	require.NoError(t, bcrypt.CompareHashAndPassword([]byte(changedUser.PasswordHash), []byte("newpassword")))
}

func Test_that_ChangePassword_fails_when_the_old_password_is_incorrect(t *testing.T) {
	u := newUsers(t)
	ctx := testContext(t)
	user, err := u.Create(ctx, testUsers[0].Name, testUsers[0].Email, testUsers[0].Password)
	require.NoError(t, err)
	require.NotNil(t, user)
	_, err = u.ChangePassword(ctx, user, "incorrect", "newpassword")
	require.ErrorIs(t, err, api.ErrUnauthorized)
}

func Test_that_ChangePassword_fails_when_the_password_is_too_long(t *testing.T) {
	u := newUsers(t)
	ctx := testContext(t)
	user, err := u.Create(ctx, testUsers[0].Name, testUsers[0].Email, testUsers[0].Password)
	require.NoError(t, err)
	require.NotNil(t, user)
	_, err = u.ChangePassword(ctx, user, testUsers[0].Password, "this password is very long and will fail because it exceeds the maximum length which is seventy-two characters")
	require.ErrorIs(t, err, api.ErrBadRequest)
}

func Test_that_RegisterResetPasswordToken_registers_a_reset_password_token(t *testing.T) {
	u := newUsers(t)
	ctx := testContext(t)
	ti := testIssuer(t)
	user, err := u.Create(ctx, testUsers[0].Name, testUsers[0].Email, testUsers[0].Password)
	require.NoError(t, err)
	require.NotNil(t, user)
	token, err := ti.Issue(user.ID, "password_reset_before", time.Now().Add(1*time.Hour).Format(time.RFC3339))
	require.NoError(t, err)
	require.NotNil(t, token)
	require.NoError(t, u.RegisterResetPasswordToken(ctx, user, string(token)))
}

func Test_that_RegisterResetPasswordToken_fails_to_register_invalid_reset_password_token(t *testing.T) {
	u := newUsers(t)
	ctx := testContext(t)
	user, err := u.Create(ctx, testUsers[0].Name, testUsers[0].Email, testUsers[0].Password)
	require.NoError(t, err)
	require.NotNil(t, user)
	token := "invalid"
	err = u.RegisterResetPasswordToken(ctx, user, token)
	require.ErrorIs(t, err, api.ErrInternalServerError)
}

func Test_that_RegisterResetPasswordToken_fails_to_register_reset_password_token_with_missing_password_reset_before_claim(t *testing.T) {
	u := newUsers(t)
	ctx := testContext(t)
	ti := testIssuer(t)
	user, err := u.Create(ctx, testUsers[0].Name, testUsers[0].Email, testUsers[0].Password)
	require.NoError(t, err)
	require.NotNil(t, user)
	token, err := ti.Issue(user.ID)
	require.NoError(t, err)
	require.NotNil(t, token)
	err = u.RegisterResetPasswordToken(ctx, user, string(token))
	require.ErrorIs(t, err, api.ErrInternalServerError)
}

func Test_that_RegisterResetPasswordToken_fails_to_register_reset_password_token_with_invalid_password_reset_before_claim(t *testing.T) {
	u := newUsers(t)
	ctx := testContext(t)
	ti := testIssuer(t)
	user, err := u.Create(ctx, testUsers[0].Name, testUsers[0].Email, testUsers[0].Password)
	require.NoError(t, err)
	require.NotNil(t, user)
	token, err := ti.Issue(user.ID, "password_reset_before", "invalid")
	require.NoError(t, err)
	require.NotNil(t, token)
	err = u.RegisterResetPasswordToken(ctx, user, string(token))
	require.ErrorIs(t, err, api.ErrInternalServerError)
}

func Test_that_RegisterResetPasswordToken_fails_to_register_reset_password_token_with_expired_password_reset_before_claim(t *testing.T) {
	u := newUsers(t)
	ctx := testContext(t)
	ti := testIssuer(t)
	user, err := u.Create(ctx, testUsers[0].Name, testUsers[0].Email, testUsers[0].Password)
	require.NoError(t, err)
	require.NotNil(t, user)
	token, err := ti.Issue(user.ID, "password_reset_before", time.Now().Add(-1*time.Hour).Format(time.RFC3339))
	require.NoError(t, err)
	require.NotNil(t, token)
	err = u.RegisterResetPasswordToken(ctx, user, string(token))
	require.ErrorIs(t, err, api.ErrBadRequest)
}

func Test_that_VerifyResetPasswordToken_verifies_the_reset_password_token(t *testing.T) {
	u := newUsers(t)
	ctx := testContext(t)
	ti := testIssuer(t)
	user, err := u.Create(ctx, testUsers[0].Name, testUsers[0].Email, testUsers[0].Password)
	require.NoError(t, err)
	require.NotNil(t, user)
	token, err := ti.Issue(user.ID, "password_reset_before", time.Now().Add(1*time.Hour).Format(time.RFC3339))
	require.NoError(t, err)
	require.NotNil(t, token)
	require.NoError(t, u.RegisterResetPasswordToken(ctx, user, string(token)))
	require.NoError(t, u.VerifyResetPasswordToken(ctx, user, string(token)))
}

func Test_that_VerifyResetPasswordToken_fails_to_accept_invalid_reset_password_token(t *testing.T) {
	u := newUsers(t)
	ctx := testContext(t)
	token := "invalid"
	user, err := u.Create(ctx, testUsers[0].Name, testUsers[0].Email, testUsers[0].Password)
	require.NoError(t, err)
	require.NotNil(t, user)
	err = u.VerifyResetPasswordToken(ctx, user, token)
	require.ErrorIs(t, err, api.ErrUnauthorized)
}

func Test_that_VerifyResetPasswordToken_fails_to_accept_same_reset_password_token_twice(t *testing.T) {
	u := newUsers(t)
	ctx := testContext(t)
	ti := testIssuer(t)
	user, err := u.Create(ctx, testUsers[0].Name, testUsers[0].Email, testUsers[0].Password)
	require.NoError(t, err)
	require.NotNil(t, user)
	token, err := ti.Issue(user.ID, "password_reset_before", time.Now().Add(1*time.Hour).Format(time.RFC3339))
	require.NoError(t, err)
	require.NotNil(t, token)
	require.NoError(t, u.RegisterResetPasswordToken(ctx, user, string(token)))
	require.NoError(t, u.VerifyResetPasswordToken(ctx, user, string(token)))
	err = u.VerifyResetPasswordToken(ctx, user, string(token))
	require.ErrorIs(t, err, api.ErrUnauthorized)
}

func Test_that_VerifyResetPasswordToken_fails_to_accept_expired_reset_password_token(t *testing.T) {
	u := newUsers(t)
	ctx := testContext(t)
	ti := testIssuer(t)
	user, err := u.Create(ctx, testUsers[0].Name, testUsers[0].Email, testUsers[0].Password)
	require.NoError(t, err)
	require.NotNil(t, user)
	// expire in 1.1 seconds - this ensures the RFC3339 format of now vs the token is different
	token, err := ti.Issue(user.ID, "password_reset_before", time.Now().Add(1100*time.Millisecond).Format(time.RFC3339))
	require.NoError(t, err)
	require.NotNil(t, token)
	require.NoError(t, u.RegisterResetPasswordToken(ctx, user, string(token)))
	// wait 2 seconds - the token is definitely expired by now
	time.Sleep(2 * time.Second)
	err = u.VerifyResetPasswordToken(ctx, user, string(token))
	require.ErrorIs(t, err, api.ErrUnauthorized)
}

func Test_that_PruneResetPasswordTokens_prunes_the_expired_reset_password_tokens(t *testing.T) {
	u := newUsers(t)
	ctx := testContext(t)
	ti := testIssuer(t)
	user, err := u.Create(ctx, testUsers[0].Name, testUsers[0].Email, testUsers[0].Password)
	require.NoError(t, err)
	require.NotNil(t, user)
	// expire in 1.1 seconds - this ensures the RFC3339 format of now vs the tok is different
	tok, err := ti.Issue(user.ID, "password_reset_before", time.Now().Add(1100*time.Millisecond).Format(time.RFC3339))
	require.NoError(t, err)
	require.NotNil(t, tok)
	require.NoError(t, u.RegisterResetPasswordToken(ctx, user, string(tok)))
	// wait 2 seconds - the token is definitely expired by now
	time.Sleep(2 * time.Second)
	require.NoError(t, u.PruneResetPasswordTokens(ctx))
	// tokens should have no rows
	tokens, err := u.cli.Token.Query().Where(uent_token.TypeEQ("reset_password")).All(ctx)
	require.NoError(t, err)
	require.Empty(t, tokens)
}

func Test_that_PruneResetPasswordTokens_does_not_prune_non_expired_reset_password_tokens(t *testing.T) {
	u := newUsers(t)
	ctx := testContext(t)
	ti := testIssuer(t)
	user, err := u.Create(ctx, testUsers[0].Name, testUsers[0].Email, testUsers[0].Password)
	require.NoError(t, err)
	require.NotNil(t, user)
	// expire in 100 seconds
	tok, err := ti.Issue(user.ID, "password_reset_before", time.Now().Add(100*time.Second).Format(time.RFC3339))
	require.NoError(t, err)
	require.NotNil(t, tok)
	require.NoError(t, u.RegisterResetPasswordToken(ctx, user, string(tok)))
	// wait 1 seconds - the token is not expired
	time.Sleep(2 * time.Second)
	require.NoError(t, u.PruneResetPasswordTokens(ctx))
	// tokens should have 1 row
	tokens, err := u.cli.Token.Query().Where(uent_token.TypeEQ("reset_password")).All(ctx)
	require.NoError(t, err)
	require.Len(t, tokens, 1)
}
