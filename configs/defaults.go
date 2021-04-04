package configs

import (
	"reflect"
)

type Defaultable interface {
	SetDefaults()
}

func SetDefaultsRecurs(s interface{}) {
	rvf := reflect.ValueOf(s)
	rv := rvf.Elem()

	rvf.MethodByName("SetDefaults").Call(nil)

	for i := 0; i < rv.NumField(); i++ {
		field := rv.Field(i)
		fieldType := field.Kind()
		if fieldType == reflect.Struct {
			SetDefaultsRecurs(field.Addr().Interface())
		} else if fieldType == reflect.Slice {
			for j := 0; j < field.Len(); j++ {
				SetDefaultsRecurs(field.Index(j).Addr().Interface())
			}
		}
	}
}

func setDefault(target interface{}, def interface{}) {
	val := reflect.ValueOf(target)
	if isZero(val.Elem()) {
		val.Elem().Set(reflect.ValueOf(def))
	}
}

func isZero(v reflect.Value) bool {
	switch v.Kind() {
	case reflect.Func, reflect.Map, reflect.Slice:
		return v.IsNil()
	case reflect.Array:
		z := true
		for i := 0; i < v.Len(); i++ {
			z = z && isZero(v.Index(i))
		}
		return z
	case reflect.Struct:
		z := true
		for i := 0; i < v.NumField(); i++ {
			z = z && isZero(v.Field(i))
		}
		return z
	}
	// Compare other types directly:
	z := reflect.Zero(v.Type())
	return v.Interface() == z.Interface()
}

// todo: run all setDefaults recursively with reflect
func (p *Project) SetDefaults() {
	println("Project")
}

func (a *app) SetDefaults() {
	println("app")
}

func (authn *Authn) SetDefaults() {
	setDefault(&authn.PathPrefix, "/")
	println("Authn")
}

func (a *Authz) SetDefaults() {
	println("Authz")
}

func (s *Storage) SetDefaults() {
	println("Storage")

}

func (c *Collection) SetDefaults() {
	println("Collection")
}

func (s *specification) SetDefaults() {
	println("specification")
}

func (h *PwHasher) SetDefaults() {
	println("PwHasher")
}

func (c *cryptoKey) SetDefaults() {
	println("cryptoKey")
}
