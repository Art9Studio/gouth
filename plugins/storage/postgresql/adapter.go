package postgresql

import (
	"aureole/internal/plugins/storage"
)

// AdapterName is the internal name of the adapter
const AdapterName = "postgresql"

// DefaultFieldType is the default type for the fields, where type is not specified
const DefaultFieldType = "text"

var AdapterFeatures = map[string]bool{
	"identity":           true,
	"session":            true,
	"pwbased":            true,
	"phone_otp":          true,
	"password_reset":     true,
	"email_link":         true,
	"email_verification": true,
}

// init initializes package by register adapter
func init() {
	storage.Repository.Register(AdapterName, pgAdapter{})
}

// pgAdapter represents adapter for postgresql database
type pgAdapter struct {
}
