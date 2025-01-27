package main

import (
	"github.com/gin-gonic/gin"
	"github.com/smxlong/app"
)

func main() {
	a := &app.Application{
		Name: "example",
		SetupFuncs: []app.SetupFunc{
			func(r *app.Resources) (app.CleanupFunc, error) {
				// Register /healthz endpoint
				r.Gin.GET("/healthz", func(c *gin.Context) {
					c.JSON(200, gin.H{"status": "ok"})
				})
				return nil, nil
			},
		},
	}
	a.Main()
}
