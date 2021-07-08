package facebook

import (
	authzT "aureole/internal/plugins/authz/types"
	storageT "aureole/internal/plugins/storage/types"
	"context"
	"github.com/gofiber/fiber/v2"
	"github.com/lestrrat-go/jwx/jwt"
)

func GetAuthCode(f *facebook) func(*fiber.Ctx) error {
	return func(c *fiber.Ctx) error {
		u := f.provider.AuthCodeURL("state")
		return c.Redirect(u)
	}
}

func Login(f *facebook) func(*fiber.Ctx) error {
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

		t, err := f.provider.Exchange(context.Background(), code)
		if err != nil {
			return sendError(c, fiber.StatusBadRequest, err.Error())
		}

		idToken := t.Extra("id_token")
		jwtT, err := jwt.ParseString(idToken.(string))
		if err != nil {
			return sendError(c, fiber.StatusBadRequest, err.Error())
		}

		email, _ := jwtT.Get("email")
		s := &f.coll.Spec
		exist, err := f.storage.IsSocialAuthExist(s, s.FieldsMap["email"].Name, email, s.FieldsMap["provider"].Name, "facebook")
		if err != nil {
			return sendError(c, fiber.StatusInternalServerError, err.Error())
		}

		var socAuth *storageT.SocialAuthData

		if !exist {
			socAuth = &storageT.SocialAuthData{Provider: "facebook"}
			socAuth.Email = email
			socAuth.SocialId, _ = jwtT.Get("sub")
			//socAuth.Additional = getAdditionalData(f, jwtT)
			userData, err := jwtT.AsMap(context.Background())
			if err != nil {
				return sendError(c, fiber.StatusInternalServerError, err.Error())
			}
			socAuth.UserData = userData

			_, err = f.storage.InsertSocialAuth(s, socAuth)
			if err != nil {
				return sendError(c, fiber.StatusInternalServerError, err.Error())
			}
		} else {
			rawSocAuth, err := f.storage.GetSocialAuth(s, s.FieldsMap["email"].Name, email, s.FieldsMap["provider"].Name, "facebook")
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

		return f.authorizer.Authorize(c, &authzCtx)
	}
}

/*func getAdditionalData(f *facebook, t jwt.Token) map[string]interface{} {
	additionalData := map[string]interface{}{}

	for collName, tokenName := range f.conf.FieldsMap {
		val, ok := t.Get(tokenName)
		if ok {
			additionalData[collName] = val
		}
	}

	return additionalData
}*/
