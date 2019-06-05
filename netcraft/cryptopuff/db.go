package cryptopuff

import (
	"crypto/rsa"
	"crypto/x509"
	"database/sql"
	"encoding/json"
	"fmt"
	"time"

	"github.com/mattn/go-sqlite3"
	"github.com/pkg/errors"
	"gitlab.netcraft.com/netcraft/recruitment/cryptopuff/database"
	"gitlab.netcraft.com/netcraft/recruitment/cryptopuff/database/sqlite"
)

var ErrUnknownParent = errors.New("cryptopuff: unknown parent block")

type InvalidBlockError struct {
	Message string
	Cause   error
}

func (i InvalidBlockError) Error() string {
	if i.Cause != nil {
		return fmt.Sprintf("%v: %v", i.Message, i.Cause)
	}
	return i.Message
}

type DB struct {
	db *database.DB
}

func OpenDB(dsn string) (*DB, error) {
	db, err := sqlite.Open(fmt.Sprintf("%v?_foreign_keys=on&_busy_timeout=60000", dsn))
	if err != nil {
		return nil, errors.Wrap(err, "cryptopuff: opening sqlite database failed")
	}

	if err := migrate(db); err != nil {
		db.Close()
		return nil, errors.Wrap(err, "cryptopuff: migration failed")
	}

	return &DB{
		db: db,
	}, nil
}

func migrate(db *database.DB) error {
	return db.TransactWithRetry(func(tx *sql.Tx) error {
		if _, err := tx.Exec(`
			CREATE TABLE IF NOT EXISTS blocks (
				hash TEXT PRIMARY KEY NOT NULL,
				previous_hash TEXT NULL,
				height INTEGER NOT NULL,
				block TEXT NOT NULL,
				FOREIGN KEY (previous_hash) REFERENCES blocks (hash)
			)
		`); err != nil {
			return err
		}

		if _, err := tx.Exec(`CREATE INDEX IF NOT EXISTS blocks_height ON blocks (height)`); err != nil {
			return err
		}

		if _, err := tx.Exec(`CREATE INDEX IF NOT EXISTS blocks_previous_hash ON blocks (previous_hash)`); err != nil {
			return err
		}

		b, err := json.Marshal(GenesisBlock)
		if err != nil {
			return err
		}
		if _, err := tx.Exec(`
			INSERT OR IGNORE INTO blocks (hash, previous_hash, height, block)
			VALUES (?, ?, ?, ?)
		`, GenesisBlock.Hash, GenesisBlock.PreviousHash, GenesisBlock.Height, b); err != nil {
			return err
		}

		if _, err := tx.Exec(`
			CREATE TABLE IF NOT EXISTS balances (
				block_hash TEXT NOT NULL,
				address TEXT NOT NULL,
				balance INTEGER NOT NULL,
				PRIMARY KEY (block_hash, address),
				FOREIGN KEY (block_hash) REFERENCES blocks (hash)
			)
		`); err != nil {
			return err
		}

		if _, err := tx.Exec(`CREATE INDEX IF NOT EXISTS balances_balance ON balances (balance)`); err != nil {
			return err
		}

		if _, err := tx.Exec(`
			CREATE TABLE IF NOT EXISTS keys (
				address TEXT PRIMARY KEY NOT NULL,
				private_key TEXT NOT NULL
			)
		`); err != nil {
			return err
		}

		if _, err := tx.Exec(`
			CREATE TABLE IF NOT EXISTS miner_address (
				address TEXT NOT NULL
			)
		`); err != nil {
			return err
		}

		var unused int64
		err = tx.QueryRow(`SELECT 1 FROM keys LIMIT 1`).Scan(&unused)
		if err == sql.ErrNoRows {
			k, err := GenerateKey(DefaultKeyLength, time.Now().Unix())
			if err != nil {
				return err
			}

			a := AddressFromKey(DefaultVersion, &k.PublicKey)
			if err := addKey(tx, a, k); err != nil {
				return err
			}

			if _, err := tx.Exec(`INSERT INTO miner_address (address) VALUES (?)`, a); err != nil {
				return err
			}
		} else if err != nil {
			return err
		}

		if _, err := tx.Exec(`
			CREATE TABLE IF NOT EXISTS txs (
				hash TEXT PRIMARY KEY NOT NULL,
				source TEXT NOT NULL,
				destination TEXT NOT NULL,
				amount INTEGER NOT NULL,
				fee INTEGER NOT NULL,
				tx TEXT NOT NULL
			)
		`); err != nil {
			return err
		}

		if _, err := tx.Exec(`CREATE INDEX IF NOT EXISTS txs_source ON txs (source)`); err != nil {
			return err
		}

		if _, err := tx.Exec(`CREATE INDEX IF NOT EXISTS txs_destination ON txs (destination)`); err != nil {
			return err
		}

		if _, err := tx.Exec(`CREATE INDEX IF NOT EXISTS txs_fee ON txs (fee)`); err != nil {
			return err
		}

		if _, err := tx.Exec(`
			CREATE TABLE IF NOT EXISTS block_txs (
				block_hash TEXT NOT NULL,
				tx_hash TEXT NOT NULL,
				PRIMARY KEY (block_hash, tx_hash),
				FOREIGN KEY (block_hash) REFERENCES blocks (hash),
				FOREIGN KEY (tx_hash) REFERENCES txs (hash)
			)
		`); err != nil {
			return err
		}

		if _, err := tx.Exec(`CREATE INDEX IF NOT EXISTS block_txs_tx_hash ON block_txs (tx_hash)`); err != nil {
			return err
		}

		if _, err := tx.Exec(`
			CREATE TABLE IF NOT EXISTS included_txs (
				block_hash TEXT NOT NULL,
				tx_hash TEXT NOT NULL,
				PRIMARY KEY (block_hash, tx_hash),
				FOREIGN KEY (block_hash) REFERENCES blocks (hash),
				FOREIGN KEY (tx_hash) REFERENCES txs (hash)
			)
		`); err != nil {
			return err
		}

		if _, err := tx.Exec(`CREATE INDEX IF NOT EXISTS included_txs_tx_hash ON included_txs (tx_hash)`); err != nil {
			return err
		}

		if _, err := tx.Exec(`
			CREATE TABLE IF NOT EXISTS peers (
				peer TEXT PRIMARY KEY NOT NULL
			)
		`); err != nil {
			return err
		}

		return nil
	})
}

func (d *DB) BestBlock() (*Block, error) {
	var b *Block
	if err := d.db.TransactWithRetry(func(tx *sql.Tx) error {
		var raw []byte
		if err := tx.QueryRow(`
			SELECT block
			FROM blocks
			ORDER BY height DESC
			LIMIT 1
		`).Scan(&raw); err != nil {
			return err
		}

		var err error
		b, err = DecodeBlock(raw)
		return err
	}); err != nil {
		return nil, err
	}
	return b, nil
}

func (d *DB) Blocks() ([]Block, error) {
	var blocks []Block
	if err := d.db.TransactWithRetry(func(tx *sql.Tx) error {
		blocks = nil

		rows, err := tx.Query(`
			WITH RECURSIVE f (previous_hash, block) AS (
				SELECT previous_hash, block FROM (
					SELECT previous_hash, block
					FROM blocks
					ORDER BY height DESC
					LIMIT 1
				)
				UNION
				SELECT b.previous_hash, b.block
				FROM blocks AS b
				JOIN f ON f.previous_hash = b.hash
			)
			SELECT block FROM f;
		`)
		if err != nil {
			return err
		}
		defer rows.Close()

		for rows.Next() {
			var raw []byte
			if err := rows.Scan(&raw); err != nil {
				return err
			}

			b, err := DecodeBlock(raw)
			if err != nil {
				return err
			}
			blocks = append(blocks, *b)
		}

		return rows.Err()
	}); err != nil {
		return nil, err
	}
	return blocks, nil
}

func (d *DB) AddBlocks(blocks []Block) error {
	return d.db.TransactWithRetry(func(tx *sql.Tx) error {
		// find the index of the most recent block in the chain that is also in
		// our local database
		divergedAt := -1

		for i, block := range blocks {
			var unused int
			err := tx.QueryRow(`SELECT 1 FROM blocks WHERE hash = ?`, block.Hash).Scan(&unused)
			if err == sql.ErrNoRows {
				continue
			} else if err != nil {
				return err
			}

			divergedAt = i
			break
		}

		if divergedAt <= 0 {
			// ignore this chain, there is no common ancestor
			return nil
		}

		for i := divergedAt - 1; i >= 0; i-- {
			block := &blocks[i]
			if err := addBlock(tx, block); err != nil {
				return err
			}
		}
		return nil
	})
}

func addBlock(tx *sql.Tx, block *Block) error {
	var raw []byte
	err := tx.QueryRow(`
		SELECT block
		FROM blocks
		WHERE hash = ?
	`, block.PreviousHash).Scan(&raw)
	if err == sql.ErrNoRows {
		return ErrUnknownParent
	} else if err != nil {
		return err
	}

	previous, err := DecodeBlock(raw)
	if err != nil {
		return err
	}

	raw, err = json.Marshal(block)
	if err != nil {
		return err
	}
	if _, err := tx.Exec(`
		INSERT INTO blocks (hash, previous_hash, height, block)
		VALUES (?, ?, ?, ?)
	`, block.Hash, block.PreviousHash, block.Height, raw); err != nil {
		if serr, ok := err.(sqlite3.Error); ok {
			if serr.ExtendedCode == sqlite3.ErrConstraintPrimaryKey {
				// the block already exists in our database, so let's
				// immediately return without an error
				return nil
			}
		}
		return err
	}

	if _, err := tx.Exec(`
		INSERT INTO balances (block_hash, address, balance)
		SELECT ?, address, balance
		FROM balances
		WHERE block_hash = ?
	`, block.Hash, block.PreviousHash); err != nil {
		return err
	}

	if _, err := tx.Exec(`
		INSERT INTO included_txs (block_hash, tx_hash)
		SELECT ?, tx_hash
		FROM included_txs
		WHERE block_hash = ?
	`, block.Hash, block.PreviousHash); err != nil {
		return err
	}

	if err := block.Valid(previous); err != nil {
		return err
	}

	fee := block.RewardOutput.Amount
	for _, stx := range block.Transactions {
		fee += stx.Fee

		if err := validTx(tx, &stx, block.Hash); err != nil {
			return err
		}

		if _, err := tx.Exec(`
			UPDATE balances
			SET balance = balance - ?
			WHERE block_hash = ? AND address = ?
		`, stx.RequiredBalance(), block.Hash, stx.Source); err != nil {
			return err
		}

		if _, err := tx.Exec(`
			INSERT INTO balances (block_hash, address, balance)
			VALUES (?, ?, ?)
			ON CONFLICT (block_hash, address) DO UPDATE
			SET balance = balance + excluded.balance
		`, block.Hash, stx.Destination, stx.Amount); err != nil {
			return err
		}

		if err := addTx(tx, &stx); err != nil {
			return err
		}

		if _, err := tx.Exec(`
			INSERT INTO included_txs (block_hash, tx_hash)
			VALUES (?, ?)
		`, block.Hash, stx.Hash); err != nil {
			return err
		}

		if _, err := tx.Exec(`
			INSERT INTO block_txs (block_hash, tx_hash)
			VALUES (?, ?)
		`, block.Hash, stx.Hash); err != nil {
			return err
		}
	}

	if fee > 0 {
		if _, err := tx.Exec(`
			INSERT INTO balances (block_hash, address, balance)
			VALUES (?, ?, ?)
			ON CONFLICT (block_hash, address) DO UPDATE
			SET balance = balance + excluded.balance
		`, block.Hash, block.RewardOutput.Destination, fee); err != nil {
			return err
		}
	}

	_, err = tx.Exec(`DELETE FROM balances WHERE balance = 0`)
	return err
}

func (d *DB) AddBlock(block *Block) error {
	return d.db.TransactWithRetry(func(tx *sql.Tx) error {
		return addBlock(tx, block)
	})
}

func (d *DB) Addresses() ([]AddressState, error) {
	var addrs []AddressState
	if err := d.db.TransactWithRetry(func(tx *sql.Tx) error {
		addrs = nil

		rows, err := tx.Query(`
			SELECT k.address, k.private_key, COALESCE(b.balance, 0)
			FROM keys k
			LEFT JOIN balances b ON b.address = k.address AND b.block_hash = (
				SELECT hash
				FROM blocks
				ORDER BY height DESC
				LIMIT 1
			)
		`)
		if err != nil {
			return err
		}
		defer rows.Close()

		for rows.Next() {
			var (
				a       Address
				b       []byte
				balance int64
			)
			if err := rows.Scan(&a, &b, &balance); err != nil {
				return err
			}

			k, err := DecodePrivateKeyPEM(b)
			if err != nil {
				return err
			}

			addrs = append(addrs, AddressState{
				Address:   a,
				PublicKey: x509.MarshalPKCS1PublicKey(&k.PublicKey),
				Balance:   balance,
			})
		}

		return rows.Err()
	}); err != nil {
		return nil, err
	}
	return addrs, nil
}

func addKey(tx *sql.Tx, a Address, k *rsa.PrivateKey) error {
	_, err := tx.Exec(`
		INSERT OR IGNORE INTO keys (address, private_key)
		VALUES (?, ?)
	`, a, EncodePrivateKeyPEM(k))
	return err
}

func (d *DB) AddKey(version Version, k *rsa.PrivateKey) (Address, error) {
	a := AddressFromKey(version, &k.PublicKey)
	if err := d.db.TransactWithRetry(func(tx *sql.Tx) error {
		return addKey(tx, a, k)
	}); err != nil {
		return nil, err
	}
	return a, nil
}

func (d *DB) Key(a Address) (*rsa.PrivateKey, error) {
	var k *rsa.PrivateKey
	if err := d.db.TransactWithRetry(func(tx *sql.Tx) error {
		var b []byte
		if err := tx.QueryRow(`SELECT private_key FROM keys WHERE address = ?`, a).Scan(&b); err != nil {
			return err
		}

		var err error
		k, err = DecodePrivateKeyPEM(b)
		return err
	}); err != nil {
		return nil, err
	}
	return k, nil
}

func (d *DB) MinerAddress() (Address, error) {
	var a Address
	if err := d.db.TransactWithRetry(func(tx *sql.Tx) error {
		return tx.QueryRow(`SELECT address FROM miner_address`).Scan(&a)
	}); err != nil {
		return nil, err
	}
	return a, nil
}

func (d *DB) SetMinerAddress(a Address) error {
	return d.db.TransactWithRetry(func(tx *sql.Tx) error {
		_, err := tx.Exec(`UPDATE miner_address SET address = ?`, a)
		return err
	})
}

func validTx(tx *sql.Tx, stx *SignedTx, tip Hash) error {
	if err := stx.Valid(); err != nil {
		return err
	}

	var balance int64
	err := tx.QueryRow(`
		SELECT balance
		FROM balances
		WHERE block_hash = ? AND address = ?
	`, tip, stx.Source).Scan(&balance)
	if err == sql.ErrNoRows {
		balance = 0
	} else if err != nil {
		return err
	}

	if balance < stx.RequiredBalance() {
		return InvalidBlockError{Message: fmt.Sprintf("cryptopuff: insufficient balance (%v coins, %v required)", balance, stx.RequiredBalance())}
	}

	var unused int64
	err = tx.QueryRow(`
		SELECT 1
		FROM included_txs
		WHERE block_hash = ? AND tx_hash = ?
	`, tip, stx.Hash).Scan(&unused)
	if err == sql.ErrNoRows {
		/* ok */
	} else if err != nil {
		return err
	} else {
		return InvalidBlockError{Message: "cryptopuff: transaction already included in blockchain"}
	}

	return nil
}

func validTemporaryTx(tx *sql.Tx, stx *SignedTx) error {
	if err := stx.Valid(); err != nil {
		return err
	}

	var balance int64
	err := tx.QueryRow(`
		SELECT balance
		FROM temp_balances
		WHERE address = ?
	`, stx.Source).Scan(&balance)
	if err == sql.ErrNoRows {
		balance = 0
	} else if err != nil {
		return err
	}

	if balance < stx.RequiredBalance() {
		return InvalidBlockError{Message: fmt.Sprintf("cryptopuff: insufficient balance (%v coins, %v required)", balance, stx.RequiredBalance())}
	}

	return nil
}

func bestBlockHash(tx *sql.Tx) (Hash, error) {
	var tip Hash
	if err := tx.QueryRow(`
		SELECT hash
		FROM blocks
		ORDER BY height DESC
		LIMIT 1
	`).Scan(&tip); err != nil {
		return EmptyHash, err
	}
	return tip, nil
}

func addTx(tx *sql.Tx, stx *SignedTx) error {
	b, err := json.Marshal(stx)
	if err != nil {
		return err
	}

	_, err = tx.Exec(`
		INSERT OR IGNORE INTO txs (hash, source, destination, amount, fee, tx)
		VALUES (?, ?, ?, ?, ?, ?)
	`, stx.Hash, stx.Source, stx.Destination, stx.Amount, stx.Fee, b)
	return err
}

func (d *DB) AddTx(stx *SignedTx) error {
	return d.db.TransactWithRetry(func(tx *sql.Tx) error {
		tip, err := bestBlockHash(tx)
		if err != nil {
			return err
		}

		if err := validTx(tx, stx, tip); err != nil {
			return err
		}

		return addTx(tx, stx)
	})
}

func (d *DB) MyTxs() ([]PersonalTx, error) {
	var ptxs []PersonalTx
	if err := d.db.TransactWithRetry(func(tx *sql.Tx) error {
		ptxs = nil

		hash, err := bestBlockHash(tx)
		if err != nil {
			return err
		}

		rows, err := tx.Query(`
			SELECT DISTINCT
				t.tx,
				i.tx_hash IS NOT NULL AS included,
				b.height
			FROM txs t
			JOIN keys k ON k.address = t.source OR k.address = t.destination
			LEFT JOIN included_txs i ON i.tx_hash = t.hash AND i.block_hash = ?
			LEFT JOIN block_txs bt ON bt.tx_hash = t.hash
			LEFT JOIN blocks b ON b.hash = bt.block_hash
			ORDER BY included ASC, b.height DESC
		`, hash)
		if err != nil {
			return err
		}
		defer rows.Close()

		for rows.Next() {
			var (
				b        []byte
				included bool
				height   sql.NullInt64
			)
			if err := rows.Scan(&b, &included, &height); err != nil {
				return err
			}

			var stx SignedTx
			if err := json.Unmarshal(b, &stx); err != nil {
				return err
			}
			if err := stx.UpdateHash(); err != nil {
				return err
			}
			ptxs = append(ptxs, PersonalTx{
				SignedTx: stx,
				Included: included,
				Height:   height.Int64,
			})
		}

		return rows.Err()
	}); err != nil {
		return nil, err
	}
	return ptxs, nil
}

func (d *DB) AllPendingTxs() ([]SignedTx, error) {
	var stxs []SignedTx
	if err := d.db.TransactWithRetry(func(tx *sql.Tx) error {
		stxs = nil

		tip, err := bestBlockHash(tx)
		if err != nil {
			return err
		}

		rows, err := tx.Query(`
			SELECT tx
			FROM txs t
			LEFT JOIN included_txs i ON i.tx_hash = t.hash AND i.block_hash = ?
			WHERE i.tx_hash IS NULL
		`, tip)
		if err != nil {
			return err
		}
		defer rows.Close()

		for rows.Next() {
			var b []byte
			if err := rows.Scan(&b); err != nil {
				return err
			}

			var stx SignedTx
			if err := json.Unmarshal(b, &stx); err != nil {
				return err
			}
			if err := stx.UpdateHash(); err != nil {
				return err
			}
			stxs = append(stxs, stx)
		}

		return rows.Err()
	}); err != nil {
		return nil, err
	}
	return stxs, nil
}

func (d *DB) PendingTxs(tip Hash, limit int) ([]SignedTx, error) {
	var stxs []SignedTx
	if err := d.db.TransactWithRetry(func(tx *sql.Tx) error {
		stxs = nil

		if _, err := tx.Exec(`DROP TABLE IF EXISTS temp_balances`); err != nil {
			return err
		}

		if _, err := tx.Exec(`
			CREATE TEMPORARY TABLE temp_balances (
				address TEXT PRIMARY KEY NOT NULL,
				balance INTEGER NOT NULL
			)
		`); err != nil {
			return err
		}

		if _, err := tx.Exec(`
			INSERT INTO temp_balances (address, balance)
			SELECT address, balance
			FROM balances
			WHERE block_hash = ?
		`, tip); err != nil {
			return err
		}

		rows, err := tx.Query(`
			SELECT tx
			FROM txs t
			LEFT JOIN included_txs i ON i.tx_hash = t.hash AND i.block_hash = ?
			WHERE i.tx_hash IS NULL
		`, tip)
		if err != nil {
			return err
		}
		defer rows.Close()

		for rows.Next() {
			var b []byte
			if err := rows.Scan(&b); err != nil {
				return err
			}

			var stx SignedTx
			if err := json.Unmarshal(b, &stx); err != nil {
				return err
			}
			if err := stx.UpdateHash(); err != nil {
				return err
			}

			// Re-validate the transaction - the source balance could have
			// changed.
			err := validTemporaryTx(tx, &stx)
			if _, ok := err.(InvalidBlockError); ok {
				if _, err := tx.Exec(`
					DELETE FROM txs
					WHERE hash = ?
					AND NOT EXISTS (
						SELECT 1
						FROM block_txs
						WHERE tx_hash = ?
					)
					AND NOT EXISTS (
						SELECT 1
						FROM included_txs
						WHERE tx_hash = ?
					)
				`, stx.Hash, stx.Hash, stx.Hash); err != nil {
					return err
				}
				continue
			} else if err != nil {
				return err
			}
			stxs = append(stxs, stx)

			if _, err := tx.Exec(`
				UPDATE temp_balances
				SET balance = balance - ?
				WHERE address = ?
			`, stx.RequiredBalance(), stx.Source); err != nil {
				return err
			}

			if _, err := tx.Exec(`
				INSERT INTO temp_balances (address, balance)
				VALUES (?, ?)
				ON CONFLICT (address) DO UPDATE
				SET balance = balance + excluded.balance
			`, stx.Destination, stx.Amount); err != nil {
				return err
			}

			if len(stxs) >= limit {
				break
			}
		}

		if err := rows.Err(); err != nil {
			return err
		}

		_, err = tx.Exec(`DROP TABLE temp_balances`)
		return err
	}); err != nil {
		return nil, err
	}
	return stxs, nil
}

func (d *DB) Peers() ([]string, error) {
	var peers []string
	if err := d.db.TransactWithRetry(func(tx *sql.Tx) error {
		peers = nil

		rows, err := tx.Query(`SELECT peer FROM peers`)
		if err != nil {
			return err
		}
		defer rows.Close()

		for rows.Next() {
			var peer string
			if err := rows.Scan(&peer); err != nil {
				return err
			}
			peers = append(peers, peer)
		}

		return rows.Err()
	}); err != nil {
		return nil, err
	}
	return peers, nil
}

func (d *DB) PeerExists(peer string) (bool, error) {
	err := d.db.TransactWithRetry(func(tx *sql.Tx) error {
		var unused int
		return tx.QueryRow(`SELECT 1 FROM peers WHERE peer = ?`, peer).Scan(&unused)
	})
	if err == sql.ErrNoRows {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	return true, nil
}

func (d *DB) AddPeer(peer string) (bool, error) {
	var created bool
	err := d.db.TransactWithRetry(func(tx *sql.Tx) error {
		r, err := tx.Exec(`INSERT OR IGNORE INTO peers (peer) VALUES (?)`, peer)
		if err != nil {
			return err
		}

		n, err := r.RowsAffected()
		if err != nil {
			return err
		}

		if n > 0 {
			created = true
		}
		return nil
	})
	if err != nil {
		return false, err
	}
	return created, nil
}

func (d *DB) RemovePeer(peer string) error {
	return d.db.TransactWithRetry(func(tx *sql.Tx) error {
		_, err := tx.Exec(`DELETE FROM peers WHERE peer = ?`, peer)
		return err
	})
}

func (d *DB) Close() error {
	if err := d.db.Close(); err != nil {
		return errors.Wrap(err, "cryptopuff: closing database failed")
	}
	return nil
}
