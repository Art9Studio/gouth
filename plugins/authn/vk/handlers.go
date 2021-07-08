package vk

import (
	authzT "aureole/internal/plugins/authz/types"
	storageT "aureole/internal/plugins/storage/types"
	"context"
	"encoding/json"
	"fmt"
	"github.com/gofiber/fiber/v2"
	"net/url"
	"strings"
)

func GetAuthCode(v *vk) func(*fiber.Ctx) error {
	return func(c *fiber.Ctx) error {
		u := v.provider.AuthCodeURL("state")
		return c.Redirect(u)
	}
}

func Login(v *vk) func(*fiber.Ctx) error {
	return func(c *fiber.Ctx) error {
		// todo: add csrf protection via "state"
		state := c.Query("state")
		if state != "state" {
			return sendError(c, fiber.StatusBadRequest, "invalid state")
		}

		code := c.Query("code")
		if code == "" {
			return sendError(c, fiber.StatusBadRequest, "code not found")
		}

		t, err := v.provider.Exchange(context.Background(), code)
		if err != nil {
			return sendError(c, fiber.StatusBadRequest, err.Error())
		}

		u, err := getUrl(v)
		if err != nil {
			return sendError(c, fiber.StatusInternalServerError, err.Error())
		}

		client := v.provider.Client(context.Background(), t)
		resp, err := client.Get(u)
		if err != nil {
			return sendError(c, fiber.StatusInternalServerError, err.Error())
		}
		_ = resp

		var data map[string]interface{}
		if err := json.NewDecoder(resp.Body).Decode(&data); err != nil {
			return sendError(c, fiber.StatusBadRequest, err.Error())
		}
		userArr := data["response"].([]interface{})
		userData := userArr[0].(map[string]interface{})

		var exist bool
		s := &v.coll.Spec
		email := t.Extra("email")
		if email != nil {
			exist, err = v.storage.IsSocialAuthExist(s, s.FieldsMap["email"].Name, email, s.FieldsMap["provider"].Name, "vk")
			if err != nil {
				return sendError(c, fiber.StatusInternalServerError, err.Error())
			}
		} else {
			socialId := t.Extra("user_id")
			exist, err = v.storage.IsSocialAuthExist(s, s.FieldsMap["social_id"].Name, socialId, s.FieldsMap["provider"].Name, "vk")
			if err != nil {
				return sendError(c, fiber.StatusInternalServerError, err.Error())
			}
		}

		var socAuth *storageT.SocialAuthData

		if !exist {
			socAuth = &storageT.SocialAuthData{Provider: "vk"}
			socAuth.Email = email
			userId := t.Extra("user_id").(float64)
			socAuth.SocialId = fmt.Sprintf("%f", userId)
			//socAuth.Additional = getAdditionalData(v, userData)
			socAuth.UserData = userData

			_, err := v.storage.InsertSocialAuth(s, socAuth)
			if err != nil {
				return sendError(c, fiber.StatusInternalServerError, err.Error())
			}
		} else {
			var rawSocAuth storageT.JSONCollResult
			if email != nil {
				rawSocAuth, err = v.storage.GetSocialAuth(s, s.FieldsMap["email"].Name, email, s.FieldsMap["provider"].Name, "vk")
				if err != nil {
					return sendError(c, fiber.StatusInternalServerError, err.Error())
				}
			} else {
				rawSocAuth, err = v.storage.GetSocialAuth(s, s.FieldsMap["social_id"].Name, t.Extra("user_id"), s.FieldsMap["provider"].Name, "vk")
				if err != nil {
					return sendError(c, fiber.StatusInternalServerError, err.Error())
				}
			}

			socAuth = storageT.NewSocialAuthData(rawSocAuth.(map[string]interface{}), s.FieldsMap)
		}

		authzCtx := authzT.Context{
			SocialId:   socAuth.SocialId,
			Email:      socAuth.Email,
			UserData:   socAuth.UserData,
			Additional: socAuth.Additional,
		}

		return v.authorizer.Authorize(c, &authzCtx)
	}
}

func getUrl(v *vk) (string, error) {
	u, err := url.Parse("https://api.vk.com/method/users.get")
	if err != nil {
		return "", err
	}

	q := u.Query()
	q.Set("v", fmt.Sprintf("%f", 5.131))
	fieldsStr := strings.Join(v.conf.Fields, ",")
	q.Set("fields", fieldsStr)
	u.RawQuery = q.Encode()

	return u.String(), nil
}

/*func getAdditionalData(g *vk, data map[string]interface{}) map[string]interface{} {
	additionalData := map[string]interface{}{}

	for collName, tokenName := range g.conf.FieldsMap {
		val, ok := data[tokenName]
		if ok {
			additionalData[collName] = val
		}
	}

	return additionalData
}*/
