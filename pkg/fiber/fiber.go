package fiber

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/mrshanahan/quemot-dev-auth-client/internal/cache"
	"github.com/mrshanahan/quemot-dev-auth-client/pkg/auth"
	"golang.org/x/oauth2"
)

var nonceCache *cache.TimedCache[string] = cache.NewTimedCache[string](5*time.Minute, 100)

func createNonce() (string, error) {
	randomBytes := make([]byte, 32)
	_, err := rand.Read(randomBytes)
	if err != nil {
		return "", err
	}
	nonce := base64.StdEncoding.EncodeToString(randomBytes)
	nonceCache.Insert(nonce)
	return nonce, nil
}

func NewLoginController(stateFunc func(*fiber.Ctx) *auth.State) func(*fiber.Ctx) error {
	return func(c *fiber.Ctx) error {
		state := stateFunc(c)
		nonce, err := createNonce()
		if err != nil {
			return err // TODO: Do something else here?
		}

		stateParam, err := state.Encode(nonce)
		if err != nil {
			return err // TODO: Do something else here?
		}
		url := auth.AuthConfig.LoginConfig.AuthCodeURL(stateParam)

		c.Status(fiber.StatusSeeOther)
		c.Redirect(url)
		return c.JSON(url)
	}
}

func NewCallbackController(handleToken func(*fiber.Ctx, *auth.State, *oauth2.Token) error) func(*fiber.Ctx) error {
	return func(c *fiber.Ctx) error {
		stateParam := c.Query("state")
		state, nonce, err := auth.ParseState(stateParam)
		if err != nil {
			c.Status(fiber.StatusUnauthorized)
			return c.SendString(fmt.Sprintf("state is invalid: %s", err))
		}
		if _, ok := nonceCache.GetAndRemove(nonce); !ok {
			c.Status(fiber.StatusUnauthorized)
			return c.SendString("state is invalid: nonce not found in cache")
		}

		code := c.Query("code")
		kcConfig := auth.AuthConfig.LoginConfig
		token, err := kcConfig.Exchange(context.Background(), code)
		if err != nil {
			return c.SendString("Code-Token Exchange Failed")
		}

		_, err = auth.VerifyToken(c.Context(), token.AccessToken)
		if err != nil {
			return c.SendStatus(401)
		}

		return handleToken(c, state, token)
	}
}
