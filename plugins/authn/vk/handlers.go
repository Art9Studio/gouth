package vk

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/gofiber/fiber/v2"
	"github.com/lestrrat-go/jwx/jwt"
	"github.com/thecasualcoder/godash"
	"net/url"
	"strings"
)

func GetAuthCode(v *vk) func(*fiber.Ctx) error {
	return func(c *fiber.Ctx) error {
		url := v.provider.AuthCodeURL("state")
		return c.Redirect(url)
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

		var respJson map[string]interface{}
		if err := json.NewDecoder(resp.Body).Decode(&respJson); err != nil {
			return sendError(c, fiber.StatusBadRequest, err.Error())
		}

		/*idToken := t.Extra("id_token")
		jwtT, err := jwt.ParseString(idToken.(string))
		if err != nil {
			return sendError(c, fiber.StatusBadRequest, err.Error())
		}

		email, _ := jwtT.Get("email")
		s := &v.coll.Spec
		exist, err := v.storage.IsSocialAuthExist(s, s.FieldsMap["email"].Name, email)
		if err != nil {
			return sendError(c, fiber.StatusInternalServerError, err.Error())
		}

		var socAuth *storageT.SocialAuthData

		if !exist {
			socAuth = &storageT.SocialAuthData{Provider: "vk"}
			socAuth.Email = email
			socAuth.SocialId, _ = jwtT.Get("sub")
			socAuth.Additional = getAdditionalData(v, jwtT)
			socAuth.UserData, err = json.MarshalIndent(jwtT, "", "  ")
			if err != nil {
				return sendError(c, fiber.StatusInternalServerError, err.Error())
			}

			_, err := v.storage.InsertSocialAuth(s, socAuth)
			if err != nil {
				return sendError(c, fiber.StatusInternalServerError, err.Error())
			}
		} else {
			rawSocAuth, err := v.storage.GetSocialAuth(s, s.FieldsMap["email"].Name, email)
			if err != nil {
				return sendError(c, fiber.StatusInternalServerError, err.Error())
			}

			socAuth = storageT.NewSocialAuthData(rawSocAuth.(map[string]interface{}), s.FieldsMap)
		}

		authzCtx := authzT.Context{
			SocialId:   socAuth.SocialId,
			Email:      socAuth.Email,
			UserData:   socAuth.UserData,
			Additional: socAuth.Additional,
		}

		return v.authorizer.Authorize(c, &authzCtx)*/
		return nil
	}
}

func getUrl(v *vk) (string, error) {
	u, err := url.Parse("https://api.vk.com/method/users.get")
	if err != nil {
		return "", err
	}

	q := u.Query()
	q.Set("v", fmt.Sprintf("%f", v.conf.Api.Version))

	var fields []string
	if err = godash.Map(v.conf.FieldsMap, &fields, func(key, val string) string {
		return val
	}); err != nil {
		return "", err
	}

	fields = union(fields, v.conf.Api.Fields)
	fieldsStr := strings.Join(fields, ",")
	q.Set("fields", fieldsStr)
	u.RawQuery = q.Encode()

	return u.String(), nil
}

func getAdditionalData(g *vk, t jwt.Token) map[string]interface{} {
	additionalData := map[string]interface{}{}

	for collName, tokenName := range g.conf.FieldsMap {
		val, ok := t.Get(tokenName)
		if ok {
			additionalData[collName] = val
		}
	}

	return additionalData
}
