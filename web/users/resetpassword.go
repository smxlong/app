package users

import (
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/lestrrat-go/jwx/v3/jwt"
	users_api "github.com/smxlong/app/api/users"
	"github.com/smxlong/app/token"
	"github.com/smxlong/app/users"
	"github.com/smxlong/kit/logger"
)

// RequestResetPassword handles the request reset password endpoint
func RequestResetPassword(l logger.Logger, ti *token.Issuer, u *users.Users) gin.HandlerFunc {
	return func(c *gin.Context) {
		ctx := c.Request.Context()
		var req users_api.RequestResetPasswordRequest
		if err := c.BindJSON(&req); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}
		user, err := u.FindByEmail(ctx, req.Email)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}
		// Create a reset password token
		jwtBytes, err := ti.Issue(user.ID, "password_reset_before", time.Now().Add(24*time.Hour).Format(time.RFC3339))
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}
		jwt := string(jwtBytes)
		if err := u.RegisterResetPasswordToken(ctx, user, jwt); err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}
		l.Infow("reset password token created", "token", jwt)
		c.JSON(http.StatusOK, gin.H{"message": "email sent"})
	}
}

// ResetPassword handles the reset password endpoint
func ResetPassword(l logger.Logger, ti *token.Issuer, u *users.Users) gin.HandlerFunc {
	return func(c *gin.Context) {
		ctx := c.Request.Context()
		var req users_api.ResetPasswordRequest
		if err := c.BindJSON(&req); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}
		jwtVal := c.MustGet("jwt").(string)
		user := c.MustGet("user").(*users.User)
		token := c.MustGet("claims").(jwt.Token)
		var prb string
		if err := token.Get("password_reset_before", &prb); err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}
		passwordResetBefore, err := time.Parse(time.RFC3339, prb)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}
		if time.Now().After(passwordResetBefore) {
			c.JSON(http.StatusBadRequest, gin.H{"error": "token expired"})
			return
		}
		if err := u.VerifyResetPasswordToken(ctx, user, jwtVal); err != nil {
			l.Infow("invalid reset password token", "token", jwtVal)
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}
		l.Infow("reset password token verified and consumed", "token", jwtVal)
		if _, err := u.ResetPassword(ctx, user, req.NewPassword); err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}
		c.JSON(http.StatusOK, gin.H{"message": "password reset"})
	}
}
