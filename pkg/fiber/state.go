package fiber

import (
	"encoding/base64"

	"github.com/gofiber/fiber/v2"
)

type OriginState struct {
	CameFrom string `json:"came_from"`
}

func OriginStateFactory(paramName string) func(c *fiber.Ctx) OriginState {
	return func(c *fiber.Ctx) OriginState {
		param := c.Params(paramName)
		var cameFrom string
		if param != "" {
			cameFromBytes, err := base64.URLEncoding.DecodeString(param)
			if err == nil {
				cameFrom = string(cameFromBytes)
			}
		}

		return OriginState{CameFrom: cameFrom}
	}
}
