# quemot.dev Golang authn/authz client library

```bash
go get github.com/mrshanahan/quemot-dev-auth-client
```

This is a library that abstracts out common functions for authenticating with an OIDC provider (specifically Keycloak) as setup for quemot.dev.

To initialize auth for a service, just call `InitializeAuth` in your service's startup:

```golang
import "github.com/mrshanahan/quemot-dev-auth-client/pkg/auth"

func main() {
    // ...
    auth.InitializeAuth(context.Background(), "my-app-client", "https://auth.quemot.dev/", "https://my-app.quemot.dev")
}
```

This will setup a singleton config that loads the proper OIDC settings from the authorization server. You can then use standard libraries to redirect to the server & validate tokens.

## Example: Fiber-based web service

```golang
import (
    "context"
    "encoding/base64"
    "fmt"

    "github.com/gofiber/fiber/v2"
    "github.com/mrshanahan/quemot-dev-auth-client/pkg/auth"
)

func main() {
    // ...

    auth.InitializeAuth(context.Background(), "my-app-client", "https://auth.quemot.dev/", "https://my-app.quemot.dev")

    app := fiber.New()
    app.Route("/auth", func(authn fiber.Router) {
        authn.Get("/login", Login)
        authn.Get("/logout", Logout)
        authn.Get("/callback", AuthCallback)
    }

    // ...
}

func Login(c *fiber.Ctx) error {
    cameFromParam := c.Query("came_from")
    var cameFrom string
    if cameFromParam != "" {
        cameFromBytes, err := base64.URLEncoding.DecodeString(cameFromParam)
        if err == nil {
            cameFrom = string(cameFromBytes)
        }
    }

    state := &auth.State{CameFrom: cameFrom}
    nonce, err := createNonce()
    if err != nil {
        return err
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

func Logout(c *fiber.Ctx) error {
    c.ClearCookie(TokenCookieName)
    return c.SendString("Logout successful")
}

func AuthCallback(c *fiber.Ctx) error {
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

    c.Cookie(&fiber.Cookie{
        Name:  "access_token",
        Value: token.AccessToken,
    })

    if state.CameFrom != "" {
        c.Redirect(state.CameFrom)
    }
    return c.SendString("Login successful")
}
```

## Example: CLI

```golang
import (
    "context"
    "fmt"
    "log/slog"

    "github.com/coreos/go-oidc/v3/oidc"
    "github.com/mrshanahan/quemot-dev-auth-client/pkg/auth"
    "golang.org/x/oauth2"
)

func main() {

}

func Login() (*oauth2.Token, error) {
    token, err := LoadToken()
    if err != nil {
        return nil, err
    }

    if IsAccessTokenValid(token) {
        return token, nil
    }

    ctx := context.Background()

    if CanRefreshToken(token) {
        newToken, err := auth.AuthConfig.LoginConfig.TokenSource(ctx, token).Token()
        if err == nil {
            err = SaveToken(newToken)
            if err != nil {
                slog.Warn("could not save token", "error", err)
            }
            return newToken, nil
        }
        slog.Info("Error when refreshing token; forcing re-login", "error", err)
    }

    return performDeviceLogin(ctx)
}

func performDeviceLogin(ctx context.Context) (*oauth2.Token, error) {
    deviceAuth, err := auth.AuthConfig.LoginConfig.DeviceAuth(ctx)
    if err != nil {
        return nil, err
    }

    // TODO: Can we make this check loop tighter?
    completeUrl := deviceAuth.VerificationURIComplete
    if completeUrl != "" {
        fmt.Printf("> Visit the following URL to complete login: %s\n", completeUrl)
    } else {
        fmt.Printf("> Visit the following URL and enter the device code to complete login: %s\n", deviceAuth.VerificationURI)
        fmt.Printf("> Code: %s\n", deviceAuth.UserCode)
    }
    fmt.Printf("> Waiting for login (expires at: %s)...\n", deviceAuth.Expiry.Local())

    token, err := auth.AuthConfig.LoginConfig.DeviceAccessToken(ctx, deviceAuth)
    if err != nil {
        return nil, err // TODO: Better error message here?
    }

    err = SaveToken(token)
    if err != nil {
        slog.Warn("could not save token", "error", err)
    }

    return token, nil
}
```