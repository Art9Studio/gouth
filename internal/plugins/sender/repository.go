package sender

import (
	"aureole/configs"
	"aureole/internal/plugins/core"
	"aureole/internal/plugins/sender/types"
)

var Repository = core.InitRepository()

// Adapter defines methods for authentication plugins
type Adapter interface {
	// Create returns desired messenger depends on the given config
	Create(*configs.Sender) types.Sender
}

func InitRepository(api *core.PluginApi) {
	Repository.PluginApi = api
}
