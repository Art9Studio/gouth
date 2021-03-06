package postgresql

import (
	"aureole/internal/plugins/storage/types"
	"context"
	"errors"
	"github.com/jackc/pgx/v4"
)

// Ping returns an error if the DBMS could not be reached
func (s *Storage) Ping() error {
	var o int
	err := s.conn.QueryRow(context.Background(), "select 1").Scan(&o)
	if err != nil {
		return err
	}

	if o != 1 {
		return errors.New("got invalid data")
	}
	return nil
}

// RawExec executes the given sql query with no returning results
func (s *Storage) RawExec(sql string, args ...interface{}) error {
	_, err := s.conn.Exec(context.Background(), sql, args...)
	return err
}

// RawQuery executes the given sql query and returns results
func (s *Storage) RawQuery(sql string, args ...interface{}) (types.JSONCollResult, error) {
	var res interface{}

	err := s.conn.QueryRow(context.Background(), sql, args...).Scan(&res)
	if err != nil {
		return nil, err
	}

	return res, nil
}

func Sanitize(ident string) string {
	return pgx.Identifier.Sanitize([]string{ident})
}
