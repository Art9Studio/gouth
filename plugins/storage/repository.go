package storage

import (
	"aureole/configs"
	ctxTypes "aureole/context/types"
	"aureole/plugins"
	"aureole/plugins/storage/types"
)

var Repository = plugins.InitRepository()

// Adapter defines methods for storage plugins
type Adapter interface {
	//Create returns desired PwHasher depends on the given config
	Create(*configs.Storage) (types.Storage, error)
}

func InitRepository(context *ctxTypes.ProjectCtx) {
	Repository.ProjectCtx = context
}