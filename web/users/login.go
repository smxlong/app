package users

import (
	"net/http"

	"github.com/gin-gonic/gin"

	users_api "github.com/smxlong/app/api/users"
	"github.com/smxlong/app/token"
	"github.com/smxlong/app/users"
)

// Login handles the login endpoint
func Login(ti *token.Issuer, u *users.Users) gin.HandlerFunc {
	return func(c *gin.Context) {
		var req users_api.LoginRequest
		if err := c.BindJSON(&req); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}
		var user *users.User
		var err error
		if user, err = u.FindByName(c, req.NameOrEmail); err != nil {
			if user, err = u.FindByEmail(c, req.NameOrEmail); err != nil {
				c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid login"})
				return
			}
		}
		if user, err = u.Login(c, user, req.Password); err != nil {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid login"})
			return
		}
		jwt, err := ti.Issue(user.ID)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}
		c.JSON(http.StatusOK, gin.H{"token": string(jwt)})
	}
}
