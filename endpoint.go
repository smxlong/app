package app

import (
	"net/http"

	"github.com/gin-gonic/gin"

	"github.com/smxlong/app/api"
)

// errorResponse writes an error response to the client.
func errorResponse(c *gin.Context, err error) {
	code := api.ErrorCode(err)
	c.JSON(code, gin.H{"error": err.Error()})
}

// Endpoint returns a gin.HandlerFunc wrapping the given handler logic.
func Endpoint[Resources, Request, Response any](resources Resources, handler func(*gin.Context, Resources, Request) (Response, error)) gin.HandlerFunc {
	return func(c *gin.Context) {
		var req Request
		if err := c.BindJSON(&req); err != nil {
			errorResponse(c, err)
			return
		}
		resp, err := handler(c, resources, req)
		if err != nil {
			errorResponse(c, err)
			return
		}
		c.JSON(http.StatusOK, resp)
	}
}
