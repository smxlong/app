package users

import (
	"net/http"

	"github.com/gin-gonic/gin"

	users_api "github.com/smxlong/app/api/users"
	"github.com/smxlong/app/users"
)

// Signup handles the signup endpoint
func Signup(u *users.Users) gin.HandlerFunc {
	return func(c *gin.Context) {
		var req users_api.SignupRequest
		if err := c.BindJSON(&req); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}
		_, err := u.Create(c, req.Name, req.Email, req.Password)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}
		c.JSON(http.StatusOK, gin.H{"message": "user created"})
	}
}
