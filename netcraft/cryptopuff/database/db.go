package database

import (
	"database/sql"
	"log"
	"os"
	"time"
)

type DB struct {
	db         *sql.DB
	logger     *log.Logger
	tries      int
	backoff    func(try int) time.Duration
	isDeadlock func(err error) bool
}

type Mode int

const (
	Read Mode = iota
	Write
)

type Option func(*DB)

func Open(driverName, dataSourceName string, isDeadlock func(err error) bool, opts ...Option) (*DB, error) {
	sqlDB, err := sql.Open(driverName, dataSourceName)
	if err != nil {
		return nil, err
	}

	if err := sqlDB.Ping(); err != nil {
		sqlDB.Close()
		return nil, err
	}

	db := &DB{
		db:         sqlDB,
		logger:     log.New(os.Stderr, "", log.LstdFlags),
		tries:      3,
		backoff:    BinaryExponentialBackoff(),
		isDeadlock: isDeadlock,
	}

	for _, opt := range opts {
		opt(db)
	}

	return db, nil
}

func (d *DB) Close() error {
	return d.db.Close()
}

func Logger(l *log.Logger) Option {
	return func(db *DB) {
		db.logger = l
	}
}

func Tries(n int) Option {
	return func(db *DB) {
		db.tries = n
	}
}

func Backoff(f func(try int) time.Duration) Option {
	return func(db *DB) {
		db.backoff = f
	}
}
