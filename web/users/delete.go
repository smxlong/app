package users

import (
	"net/http"

	"github.com/gin-gonic/gin"

	users_api "github.com/smxlong/app/api/users"
	"github.com/smxlong/app/users"
)

// Delete handles the delete user endpoint
func Delete(u *users.Users) gin.HandlerFunc {
	return func(c *gin.Context) {
		var req users_api.DeleteRequest
		if err := c.BindJSON(&req); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}
		user := c.MustGet("user").(*users.User)
		if err := u.Delete(c, user, req.Password); err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}
		c.JSON(http.StatusOK, gin.H{"message": "user deleted"})
	}
}
