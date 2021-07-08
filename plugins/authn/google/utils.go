package google

import (
	"aureole/pkg/jsonpath"
	"github.com/gofiber/fiber/v2"
)

func sendError(c *fiber.Ctx, statusCode int, message string) error {
	return c.Status(statusCode).JSON(&fiber.Map{
		"success": false,
		"message": message,
	})
}

func getJsonData(json interface{}, fieldPath string, data *interface{}) (int, error) {
	jsonVal, err := jsonpath.GetJsonPath(fieldPath, json)
	if err != nil {
		return fiber.StatusBadRequest, err
	}

	*data = jsonVal
	return 0, nil
}
