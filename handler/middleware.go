package handler

import (
	"strings"

	"golang-fiber-jwt-auth/errs"
	"golang-fiber-jwt-auth/token"

	"github.com/gofiber/fiber/v2"
)

const claimsLocalsKey = "claims"

func JWTMiddleware(secret []byte) fiber.Handler {
	return func(c *fiber.Ctx) error {
		const bearerPrefix = "Bearer "

		header := c.Get("Authorization")
		if !strings.HasPrefix(header, bearerPrefix) {
			return handleError(c, errs.NewUnauthorizedError("missing bearer token"))
		}

		raw := strings.TrimPrefix(header, bearerPrefix)
		claims, err := token.Verify(secret, raw, "access")
		if err != nil {
			return handleError(c, errs.NewUnauthorizedError("invalid or expired token"))
		}

		c.Locals(claimsLocalsKey, claims)
		return c.Next()
	}
}

func RequireRole(roles ...string) fiber.Handler {
	return func(c *fiber.Ctx) error {
		claims, ok := c.Locals(claimsLocalsKey).(token.Claims)
		if !ok {
			return handleError(c, errs.NewUnauthorizedError("missing auth context"))
		}

		for _, role := range roles {
			if claims.Role == role {
				return c.Next()
			}
		}

		return handleError(c, errs.NewForbiddenError("insufficient role"))
	}
}
