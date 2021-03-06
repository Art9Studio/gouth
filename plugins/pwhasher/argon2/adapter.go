package argon2

import (
	"aureole/internal/plugins/pwhasher"
)

// AdapterName is the internal name of the adapter
const AdapterName = "argon2"

// init initializes package by register adapter
func init() {
	pwhasher.Repository.Register(AdapterName, argon2Adapter{})
}

// argon2Adapter represents adapter for argon2 pwhasher algorithm
type argon2Adapter struct {
}
