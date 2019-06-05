package sqlite

import (
	"github.com/mattn/go-sqlite3"
)

func isDeadlock(err error) bool {
	serr, ok := err.(sqlite3.Error)
	if !ok {
		return false
	}
	// XXX(gpe): SQLite is a bit of an edge case. It only permits single
	// writers, so you can't really get deadlocks in the same way as a
	// traditional RDBMS.
	//
	// https://www.sqlite.org/rescode.html documents the meaning of the error
	// codes. In particular, I'm not sure if we actually need to consider
	// ErrLocked or ErrProtocol as deadlocks.
	//
	// ErrLocked is caused by conflicts within the same connection, which will
	// presumably occur every single time we retry. I included it as there's an
	// edge case - it could be caused by another connection if the connections
	// use a shared cache.
	//
	// ErrProtocol is only returned after SQLite has attempted its own retry
	// logic, so we might not need to apply our own retry logic on top of that.
	return serr.Code == sqlite3.ErrBusy || serr.Code == sqlite3.ErrLocked || serr.Code == sqlite3.ErrProtocol
}
