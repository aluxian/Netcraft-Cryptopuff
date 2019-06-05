package database

import (
	"database/sql"
	"errors"
	"fmt"
	"time"
)

type TxError struct {
	cause error
	tries int
}

func (e TxError) Cause() error {
	return e.cause
}

func (e TxError) Error() string {
	return fmt.Sprintf("database: transaction failed after %v attempt(s): %v", e.tries, e.cause)
}

func (d *DB) Transact(f func(tx *sql.Tx) error) (err error) {
	tx, err := d.db.Begin()
	if err != nil {
		return err
	}

	defer func() {
		if err != nil {
			if rerr := tx.Rollback(); rerr != nil {
				d.logger.Printf("database: rollback failed: %s", rerr)
			}

			// Return the error from f(tx), rather than the rollback error.
			return
		}

		err = tx.Commit()
	}()

	return f(tx)
}

func (d *DB) TransactWithRetry(f func(tx *sql.Tx) error) error {
	tries := d.tries
	if tries == 0 {
		return errors.New("database: tries must be 1 or greater")
	}

	var err error
	for i := 0; i < tries; i++ {
		err = d.Transact(f)
		if err == nil {
			return nil
		}
		if !d.isDeadlock(err) {
			return err
		}
		if i != tries-1 {
			duration := d.backoff(i)
			time.Sleep(duration)
		}
	}

	return TxError{cause: err, tries: tries}
}
