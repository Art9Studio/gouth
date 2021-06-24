package google

import (
	authzT "aureole/internal/plugins/authz/types"
	storageT "aureole/internal/plugins/storage/types"
	"context"
	"encoding/json"
	"github.com/gofiber/fiber/v2"
	"github.com/lestrrat-go/jwx/jwt"
)

func GetAuthCode(g *google) func(*fiber.Ctx) error {
	return func(c *fiber.Ctx) error {
		url := g.provider.AuthCodeURL("state")
		return c.Redirect(url)
	}
}

func Login(g *google) func(*fiber.Ctx) error {
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

		t, err := g.provider.Exchange(context.Background(), code)
		if err != nil {
			return sendError(c, fiber.StatusBadRequest, err.Error())
		}

		idToken := t.Extra("id_token")
		jwtT, err := jwt.ParseString(idToken.(string))
		if err != nil {
			return sendError(c, fiber.StatusBadRequest, err.Error())
		}

		email, _ := jwtT.Get("email")
		s := &g.coll.Spec
		exist, err := g.storage.IsSocialAuthExist(s, s.FieldsMap["email"].Name, email)
		if err != nil {
			return sendError(c, fiber.StatusInternalServerError, err.Error())
		}

		var socAuth *storageT.SocialAuthData

		if !exist {
			socAuth = &storageT.SocialAuthData{Provider: "google"}
			socAuth.Email = email
			socAuth.SocialId, _ = jwtT.Get("sub")
			socAuth.Additional = getAdditionalData(g, jwtT)
			socAuth.UserData, err = json.MarshalIndent(jwtT, "", "  ")
			if err != nil {
				return sendError(c, fiber.StatusInternalServerError, err.Error())
			}

			_, err := g.storage.InsertSocialAuth(s, socAuth)
			if err != nil {
				return sendError(c, fiber.StatusInternalServerError, err.Error())
			}
		} else {
			rawSocAuth, err := g.storage.GetSocialAuth(s, s.FieldsMap["email"].Name, email)
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

		return g.authorizer.Authorize(c, &authzCtx)
	}
}

func getAdditionalData(g *google, t jwt.Token) map[string]interface{} {
	additionalData := map[string]interface{}{}

	for collName, tokenName := range g.conf.FieldsMap {
		val, ok := t.Get(tokenName)
		if ok {
			additionalData[collName] = val
		}
	}

	return additionalData
}
