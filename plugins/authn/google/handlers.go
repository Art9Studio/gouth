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
		u := g.provider.AuthCodeURL("state")
		return c.Redirect(u)
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

		var socAuth *storageT.SocialAuthData
		email, _ := jwtT.Get("email")
		s := &g.coll.Spec
		exist, err := g.storage.IsSocialAuthExist(s, s.FieldsMap["email"].Name, email, s.FieldsMap["provider"].Name, "google")
		if err != nil {
			return sendError(c, fiber.StatusInternalServerError, err.Error())
		}

		if exist {
			rawSocAuth, err := g.storage.GetSocialAuth(s, s.FieldsMap["email"].Name, email, s.FieldsMap["provider"].Name, "google")
			if err != nil {
				return sendError(c, fiber.StatusInternalServerError, err.Error())
			}
			socAuth = storageT.NewSocialAuthData(rawSocAuth, s.FieldsMap)
		} else {
			userData, err := jwtT.AsMap(context.Background())
			if err != nil {
				return sendError(c, fiber.StatusInternalServerError, err.Error())
			}

			socAuth = &storageT.SocialAuthData{
				Email:    email,
				Provider: "google",
				UserData: userData,
			}
			socAuth.SocialId, _ = jwtT.Get("sub")
			socAuth.Id, err = g.storage.InsertSocialAuth(s, socAuth)
			if err != nil {
				return sendError(c, fiber.StatusInternalServerError, err.Error())
			}
		}

		var authzCtx *authzT.Context
		if socAuth.UserId != nil {
			// fill with user data
			authzCtx = &authzT.Context{}
			return g.authorizer.Authorize(c, authzCtx)
		}

		authzCtx = &authzT.Context{
			SocialId:   socAuth.SocialId,
			Email:      socAuth.Email,
			UserData:   socAuth.UserData,
			Additional: socAuth.Additional,
		}
		if err := g.authorizer.Authorize(c, authzCtx); err != nil {
			return sendError(c, fiber.StatusInternalServerError, err.Error())
		}

		return canLinkAccount(c, g, map[string]interface{}{
			"email":     email,
			"social_id": socAuth.Id,
		})
	}
}

func canLinkAccount(c *fiber.Ctx, g *google, ctx map[string]interface{}) error {
	s := &g.identity.Collection.Spec
	exist, err := g.storage.IsIdentityExist(g.identity, s.FieldsMap["email"].Name, ctx["email"])
	if err != nil {
		return sendError(c, fiber.StatusInternalServerError, err.Error())
	}
	if exist {
		rawUser, err := g.storage.GetIdentity(g.identity, s.FieldsMap["email"].Name, ctx["email"])
		if err != nil {
			return sendError(c, fiber.StatusInternalServerError, err.Error())
		}
		user := storageT.NewIdentityData(rawUser, s.FieldsMap)

		jsonBody := make(map[string]interface{})
		if err := json.Unmarshal(c.Response().Body(), &jsonBody); err != nil {
			return sendError(c, fiber.StatusInternalServerError, err.Error())
		}
		jsonBody["can_connect"] = true
		jsonBody["social_id"] = ctx["social_id"]
		jsonBody["user_id"] = user.Id
		return c.JSON(jsonBody)
	}

	return nil
}

func LinkAccount(g *google) func(*fiber.Ctx) error {
	return func(c *fiber.Ctx) error {
		var authInput interface{}
		if err := c.BodyParser(&authInput); err != nil {
			return sendError(c, fiber.StatusBadRequest, err.Error())
		}

		conn := g.conf.Link
		socAuth := &storageT.SocialAuthData{}
		if statusCode, err := getJsonData(authInput, conn.FieldsMap["social_id"], &socAuth.Id); err != nil {
			return sendError(c, statusCode, err.Error())
		}
		user := &storageT.IdentityData{}
		if statusCode, err := getJsonData(authInput, conn.FieldsMap["user_id"], &user.Id); err != nil {
			return sendError(c, statusCode, err.Error())
		}

		s := &g.coll.Spec
		rawSocAuth, err := g.storage.GetSocialAuth(s, s.FieldsMap["id"].Name, socAuth.Id, s.FieldsMap["provider"].Name, "google")
		if err != nil {
			return sendError(c, fiber.StatusInternalServerError, err.Error())
		}
		socAuth = storageT.NewSocialAuthData(rawSocAuth, s.FieldsMap)

		userSpec := &g.identity.Collection.Spec
		exist, err := g.storage.IsIdentityExist(g.identity, userSpec.FieldsMap["id"].Name, user.Id)
		if err != nil {
			return sendError(c, fiber.StatusInternalServerError, err.Error())
		}
		if !exist {
			return sendError(c, fiber.StatusBadRequest, "user doesn't exists")
		}

		if err := g.storage.LinkAccount(s, s.FieldsMap["id"].Name, socAuth.Id, user); err != nil {
			return sendError(c, fiber.StatusInternalServerError, err.Error())
		}

		return c.JSON(fiber.Map{"message": "success"})
	}
}

/*func getAdditionalData(g *google, t jwt.Token) map[string]interface{} {
	additionalData := map[string]interface{}{}

	for collName, tokenName := range g.conf.FieldsMap {
		val, ok := t.Get(tokenName)
		if ok {
			additionalData[collName] = val
		}
	}

	return additionalData
}*/
