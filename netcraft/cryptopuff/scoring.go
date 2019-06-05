package cryptopuff

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/pkg/errors"
)

// XXX(gpe): the code in this file is only used to prove ownership of your
// wallet addresses to the master server, for scoring purposes. It would not be
// part of a normal cryptocurrency, nor is it designed to contain any
// vulnerabilities. To save time: ignore this file!

type Key struct {
	Address Address
	Key     *rsa.PrivateKey
}

func (k Key) SignAddressProof(challenge []byte) (*AddressProof, error) {
	// XXX(gpe): deliberately use a different hashing algorithm so people can't
	// exploit this endpoint to sign transactions on demand. Ideally we'd use
	// SHA-256 but that's too long for a 256-bit RSA key to sign!
	hash := sha256.Sum224(challenge)

	signature, err := rsa.SignPSS(rand.Reader, k.Key, crypto.SHA224, hash[:], nil)
	if err != nil {
		return nil, errors.Wrap(err, "cryptopuff: failed to sign address proof challenge")
	}

	return &AddressProof{
		Signature: signature,
		Address:   k.Address,
		PublicKey: x509.MarshalPKCS1PublicKey(&k.Key.PublicKey),
	}, nil
}

type AddressProof struct {
	Signature []byte
	Address   Address
	PublicKey []byte
}

func (a AddressProof) Verify(challenge []byte) error {
	k, err := x509.ParsePKCS1PublicKey(a.PublicKey)
	if err != nil {
		return errors.Wrap(err, "cryptopuff: failed to parse public key")
	}

	addressV1 := AddressFromKey(V1, k)
	addressV2 := AddressFromKey(V2, k)
	if !addressV1.Equal(a.Address) && !addressV2.Equal(a.Address) {
		return errors.New("cryptopuff: address doesn't match public key")
	}

	hash := sha256.Sum224(challenge)
	if err := rsa.VerifyPSS(k, crypto.SHA224, hash[:], a.Signature, nil); err != nil {
		return errors.Wrap(err, "cryptopuff: invalid signature")
	}
	return nil
}

func (d *DB) Keys() ([]Key, error) {
	var keys []Key
	if err := d.db.TransactWithRetry(func(tx *sql.Tx) error {
		keys = nil

		rows, err := tx.Query(`SELECT address, private_key FROM keys`)
		if err != nil {
			return err
		}
		defer rows.Close()

		for rows.Next() {
			var (
				a Address
				b []byte
			)
			if err := rows.Scan(&a, &b); err != nil {
				return err
			}

			k, err := DecodePrivateKeyPEM(b)
			if err != nil {
				return err
			}

			keys = append(keys, Key{
				Address: a,
				Key:     k,
			})
		}

		return rows.Err()
	}); err != nil {
		return nil, err
	}
	return keys, nil
}

func (d *DB) Score(addrs map[string][]Address) (map[string]int64, error) {
	var scores map[string]int64
	if err := d.db.TransactWithRetry(func(tx *sql.Tx) error {
		scores = make(map[string]int64)

		tip, err := bestBlockHash(tx)
		if err != nil {
			return err
		}

		if _, err := tx.Exec(`DROP TABLE IF EXISTS temp_addrs`); err != nil {
			return err
		}

		if _, err := tx.Exec(`
			CREATE TEMPORARY TABLE temp_addrs (
				ip TEXT NOT NULL,
				address TEXT NOT NULL,
				PRIMARY KEY (ip, address)
			)
		`); err != nil {
			return err
		}

		for k, v := range addrs {
			for _, addr := range v {
				if _, err := tx.Exec(`INSERT INTO temp_addrs (ip, address) VALUES (?, ?)`, k, addr); err != nil {
					return err
				}
			}
		}

		rows, err := tx.Query(`
			SELECT a.ip, SUM(b.balance)
			FROM temp_addrs a 
			LEFT JOIN balances b ON b.address = a.address
			WHERE b.block_hash = ?
			GROUP BY a.ip
		`, tip)
		if err != nil {
			return err
		}
		defer rows.Close()

		for rows.Next() {
			var (
				ip    string
				score int64
			)
			if err := rows.Scan(&ip, &score); err != nil {
				return err
			}
			scores[ip] = score
		}

		if err := rows.Err(); err != nil {
			return err
		}

		_, err = tx.Exec(`DROP TABLE temp_addrs`)
		return err
	}); err != nil {
		return nil, err
	}
	return scores, nil
}

func (s *Server) addressProofs(w http.ResponseWriter, r *http.Request) {
	challenge, err := hex.DecodeString(r.URL.Query().Get("challenge"))
	if err != nil {
		http.Error(w, fmt.Sprintf("cryptopuff: failed to hex decode challenge: %v", err), http.StatusBadRequest)
		return
	}

	keys, err := s.db.Keys()
	if err != nil {
		http.Error(w, fmt.Sprintf("cryptopuff: failed to select keys: %v", err), http.StatusInternalServerError)
		return
	}

	var proofs []AddressProof
	for _, key := range keys {
		proof, err := key.SignAddressProof(challenge)
		if err != nil {
			http.Error(w, fmt.Sprintf("cryptopuff: failed to sign address proof: %v", err), http.StatusInternalServerError)
			return
		}
		proofs = append(proofs, *proof)
	}

	w.Header().Set(headerContentType, contentTypeJSON)
	if err := json.NewEncoder(w).Encode(proofs); err != nil {
		http.Error(w, fmt.Sprintf("cryptopuff: failed to marshal JSON: %v", err), http.StatusInternalServerError)
		return
	}
}
