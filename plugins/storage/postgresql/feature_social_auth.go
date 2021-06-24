package postgresql

import (
	"aureole/internal/collections"
	"aureole/internal/plugins/storage/types"
	"fmt"
	"github.com/huandu/go-sqlbuilder"
)

func (s *Storage) InsertSocialAuth(spec *collections.Spec, data *types.SocialAuthData) (types.JSONCollResult, error) {
	cols := []string{
		Sanitize(spec.FieldsMap["social_id"].Name),
		Sanitize(spec.FieldsMap["provider"].Name),
		Sanitize(spec.FieldsMap["user_data"].Name),
	}
	values := []interface{}{data.SocialId, data.Provider, data.UserData}

	if data.Email != nil {
		cols = append(cols, Sanitize(spec.FieldsMap["email"].Name))
		values = append(values, data.Email)
	}

	for fieldName := range data.Additional {
		cols = append(cols, Sanitize(spec.FieldsMap[fieldName].Name))
		values = append(values, data.Additional[fieldName])
	}

	b := sqlbuilder.PostgreSQL.NewInsertBuilder()
	b.InsertInto(Sanitize(spec.Name))
	b.Cols(cols...)
	b.Values(values...)
	b.SQL(fmt.Sprintf(" returning %s", Sanitize(spec.Pk)))

	sql, args := b.Build()
	return s.RawQuery(sql, args...)
}

func (s *Storage) GetSocialAuth(spec *collections.Spec, filterField string, filterVal interface{}) (types.JSONCollResult, error) {
	from := sqlbuilder.PostgreSQL.NewSelectBuilder()
	from.Select("*").From(Sanitize(spec.Name)).Where(from.Equal(Sanitize(filterField), filterVal))

	b := sqlbuilder.PostgreSQL.NewSelectBuilder()
	b.Select("row_to_json(t)")
	b.From(b.BuilderAs(from, "t"))
	sql, args := b.Build()

	return s.RawQuery(sql, args...)
}

func (s *Storage) IsSocialAuthExist(spec *collections.Spec, filterField string, filterVal interface{}) (bool, error) {
	sql := fmt.Sprintf("select exists (select 1 from %s where %s=$1)", Sanitize(spec.Name), Sanitize(filterField))
	res, err := s.RawQuery(sql, filterVal)
	if err != nil {
		return false, err
	}

	return res.(bool), nil
}
