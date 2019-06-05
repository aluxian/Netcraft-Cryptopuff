package sqlite

import (
	_ "github.com/mattn/go-sqlite3"
	"gitlab.netcraft.com/netcraft/recruitment/cryptopuff/database"
)

func Open(dataSourceName string, opts ...database.Option) (*database.DB, error) {
	db, err := database.Open("sqlite3", dataSourceName, isDeadlock, opts...)
	if err != nil {
		return nil, err
	}
	return db, nil
}
