package core

import (
	"aureole/internal/collections"
	"aureole/internal/identity"
	authzTypes "aureole/internal/plugins/authz/types"
	cryptoKeyTypes "aureole/internal/plugins/cryptokey/types"
	pwhasherTypes "aureole/internal/plugins/pwhasher/types"
	senderTypes "aureole/internal/plugins/sender/types"
	storageTypes "aureole/internal/plugins/storage/types"
	"aureole/internal/router"
)

type PluginApi struct {
	Project projectApi
	Router  routerApi
}

type projectApi interface {
	GetCollection(name string) (*collections.Collection, error)
	GetStorage(name string) (storageTypes.Storage, error)
	GetHasher(name string) (pwhasherTypes.PwHasher, error)
	GetSender(name string) (senderTypes.Sender, error)
	GetCryptoKey(name string) (cryptoKeyTypes.CryptoKey, error)
	GetAuthorizer(name, appName string) (authzTypes.Authorizer, error)
	GetIdentity(appName string) (*identity.Identity, error)
}

type routerApi interface {
	Add(appName string, routes []*router.Route)
}

var pluginApi PluginApi

func InitApi(projApi projectApi, router routerApi) {
	pluginApi = PluginApi{Project: projApi, Router: router}
}

func (api *PluginApi) RegisterCollectionType(col *collections.CollectionType) {
	collections.Repository.Register(col)
}
