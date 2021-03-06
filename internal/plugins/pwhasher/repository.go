package pwhasher

import (
	"aureole/internal/configs"
	"aureole/internal/plugins/core"
	"aureole/internal/plugins/pwhasher/types"
)

var Repository = core.CreateRepository()

// Adapter defines methods for pwhasher plugins
type Adapter interface {
	//Create returns desired pwHasher depends on the given config
	Create(*configs.PwHasher) types.PwHasher
}
