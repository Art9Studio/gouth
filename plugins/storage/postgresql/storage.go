package postgresql

import (
	"aureole/internal/plugins/storage"
	"aureole/internal/plugins/storage/types"
	"context"
	"github.com/jackc/pgx/v4"
)

// Storage represents a postgresql database
type Storage struct {
	Conf *config
	conn *pgx.Conn
	// for abstract queries
	relInfo map[types.CollPair]types.RelInfo
}

func (s *Storage) CheckFeaturesAvailable(requiredFeatures []string) error {
	return storage.CheckFeaturesAvailable(requiredFeatures, AdapterFeatures)
}

// Open creates connection with postgresql database
func (s *Storage) Open() error {
	var url string
	var err error

	if s.Conf.Url == "" {
		url, err = s.Conf.ToURL()
		if err != nil {
			return err
		}
	} else {
		url = s.Conf.Url
	}

	conn, err := pgx.Connect(context.Background(), url)
	if err != nil {
		return err
	}

	s.conn = conn
	return nil
}

// Close terminates the currently active connection to the DBMS
func (s *Storage) Close() error {
	return s.conn.Close(context.Background())
}