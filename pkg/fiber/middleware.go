package fiber

import (
	"regexp"

	"github.com/gofiber/fiber/v2"
	"github.com/mrshanahan/quemot-dev-auth-client/pkg/auth"
)

var bearerTokenPattern *regexp.Regexp = regexp.MustCompile(`^Bearer\s+(.*)$`)

func ValidateAccessTokenMiddleware(localName string, cookieName string) func(*fiber.Ctx) error {
	return func(c *fiber.Ctx) error {
		reqHeaders := c.GetReqHeaders()
		var tokenStr string
		authHeaderValue, ok := reqHeaders["Authorization"]
		if !ok {
			// If no Authorization header, try cookie auth
			tokenStr = c.Cookies(cookieName)
		} else {
			match := bearerTokenPattern.FindStringSubmatch(authHeaderValue[0])
			if match == nil {
				return c.SendStatus(fiber.StatusUnauthorized)
			}
			tokenStr = match[1]
		}

		token, err := auth.VerifyToken(c.Context(), tokenStr)
		if err != nil {
			return c.SendStatus(fiber.StatusUnauthorized)
		}
		c.Locals(localName, token)
		return c.Next()
	}
}
