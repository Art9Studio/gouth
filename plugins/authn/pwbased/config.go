package pwbased

import (
	"aureole/internal/configs"
	authnTypes "aureole/internal/plugins/authn/types"
)

type (
	config struct {
		MainHasher    string    `mapstructure:"main_hasher"`
		CompatHashers []string  `mapstructure:"compat_hashers"`
		Collection    string    `mapstructure:"collection"`
		Storage       string    `mapstructure:"storage"`
		Login         login     `mapstructure:"login"`
		Register      register  `mapstructure:"register"`
		Reset         resetConf `mapstructure:"password_reset"`
		Verif         verifConf `mapstructure:"verification"`
	}

	login struct {
		Path      string            `mapstructure:"path"`
		FieldsMap map[string]string `mapstructure:"fields_map"`
	}

	register struct {
		Path          string            `mapstructure:"path"`
		IsLoginAfter  bool              `mapstructure:"login_after"`
		IsVerifyAfter bool              `mapstructure:"verify_after"`
		FieldsMap     map[string]string `mapstructure:"fields_map"`
	}

	resetConf struct {
		Path       string            `mapstructure:"path"`
		ConfirmUrl string            `mapstructure:"confirm_url"`
		Collection string            `mapstructure:"collection"`
		Sender     string            `mapstructure:"sender"`
		Template   string            `mapstructure:"template"`
		Token      token             `mapstructure:"token"`
		FieldsMap  map[string]string `mapstructure:"fields_map"`
	}

	verifConf struct {
		Path       string            `mapstructure:"path"`
		ConfirmUrl string            `mapstructure:"confirm_url"`
		Collection string            `mapstructure:"collection"`
		Sender     string            `mapstructure:"sender"`
		Template   string            `mapstructure:"template"`
		Token      token             `mapstructure:"token"`
		FieldsMap  map[string]string `mapstructure:"fields_map"`
	}

	token struct {
		Exp      int    `mapstructure:"exp"`
		HashFunc string `mapstructure:"hash_func"`
	}
)

func (p pwBasedAdapter) Create(conf *configs.Authn) authnTypes.Authenticator {
	return &pwBased{rawConf: conf}
}
