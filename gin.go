package app

import (
	"time"

	"github.com/gin-gonic/gin"
)

// setupGin sets up the Gin engine.
func (a *Application) setupGin(r *Resources) (CleanupFunc, error) {
	if a.debugFlag {
		gin.SetMode(gin.DebugMode)
	} else {
		gin.SetMode(gin.ReleaseMode)
	}
	r.Gin = gin.New()
	a.setupGinRequestLogging(r)
	r.Gin.Use(gin.Recovery())
	return nil, nil
}

// setupGinRequestLogging sets up request logging for the Gin engine.
func (a *Application) setupGinRequestLogging(r *Resources) {
	r.Gin.Use(func(c *gin.Context) {
		start := time.Now()
		c.Next()
		elapsed := time.Since(start)
		r.Logger.Infow("request",
			"method", c.Request.Method,
			"path", c.Request.URL.Path,
			"status", c.Writer.Status(),
			"duration", elapsed,
			"start_time", start)
	})
}
