package token

import (
	"net/http"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/lestrrat-go/jwx/v3/jwa"
	"github.com/lestrrat-go/jwx/v3/jwt"
)

// Issuer issues JWTs
type Issuer struct {
	Issuer   string
	Audience string
	ValidFor time.Duration
	Secret   []byte
}

// Issue issues a JWT for the given subject
func (t *Issuer) Issue(subject string, more ...interface{}) ([]byte, error) {
	token := jwt.New()
	token.Set(jwt.SubjectKey, subject)
	token.Set(jwt.IssuerKey, t.Issuer)
	token.Set(jwt.AudienceKey, []string{t.Audience})
	token.Set(jwt.ExpirationKey, time.Now().Add(t.ValidFor).Unix())

	// Iterate over remaining args. If an arg is a map[string]interface{}, set each key-value pair in the token.
	// If an arg is a string, set it as a key with the next arg as the value.
	for i := 0; i < len(more); i++ {
		switch v := more[i].(type) {
		case map[string]interface{}:
			for key, value := range v {
				token.Set(key, value)
			}
		case string:
			if i+1 < len(more) {
				token.Set(v, more[i+1])
				i++
			}
		}
	}

	return jwt.Sign(token, jwt.WithKey(jwa.HS256(), t.Secret))
}

// Verify verifies the given JWT and returns the parsed token
func (t *Issuer) Verify(value []byte) (jwt.Token, error) {
	token, err := jwt.Parse(value, jwt.WithIssuer(t.Issuer), jwt.WithAudience(t.Audience), jwt.WithKey(jwa.HS256(), t.Secret))
	if err != nil {
		return nil, err
	}
	return token, nil
}

// Middleware returns a middleware that verifies the JWT in the Authorization header
// and sets the following keys in the context:
// - "jwt": the JWT
// - "claims": the parsed token
// - "subject": the subject of the token
func (t *Issuer) Middleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		auth := c.GetHeader("Authorization")
		if auth == "" {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "missing Authorization header"})
			return
		}
		if !strings.HasPrefix(auth, "Bearer ") {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "invalid Authorization header"})
			return
		}
		token, err := t.Verify([]byte(auth[7:]))
		if err != nil {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "invalid token"})
			return
		}
		c.Set("jwt", auth[7:])
		c.Set("claims", token)
		sub, _ := token.Subject()
		if sub == "" {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "missing subject in token"})
			return
		}
		c.Set("subject", sub)
		c.Next()
	}
}
