package users

import (
	"net/http"

	"github.com/gin-gonic/gin"
	users_api "github.com/smxlong/app/api/users"
	"github.com/smxlong/app/users"
)

// ChangePassword handles the change password endpoint
func ChangePassword(u *users.Users) gin.HandlerFunc {
	return func(c *gin.Context) {
		var req users_api.ChangePasswordRequest
		if err := c.BindJSON(&req); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}
		user := c.MustGet("user").(*users.User)
		if _, err := u.ChangePassword(c, user, req.OldPassword, req.NewPassword); err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}
		c.JSON(http.StatusOK, gin.H{"message": "password changed"})
	}
}
