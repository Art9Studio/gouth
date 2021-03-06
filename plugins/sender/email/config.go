package email

import (
	"aureole/internal/configs"
	"aureole/internal/plugins/sender/types"
)

type config struct {
	Host      string            `mapstructure:"host"`
	Username  string            `mapstructure:"username"`
	Password  string            `mapstructure:"password"`
	From      string            `mapstructure:"from"`
	Bcc       []string          `mapstructure:"bcc"`
	Cc        []string          `mapstructure:"cc"`
	Templates map[string]string `mapstructure:"templates"`
}

func (e emailAdapter) Create(conf *configs.Sender) types.Sender {
	return &Email{rawConf: conf}
}
