package cryptopuff

import (
	"crypto/md5"
	"database/sql/driver"
	"encoding/hex"
	"encoding/json"

	"github.com/pkg/errors"
)

var EmptyHash Hash

type Hash [md5.Size]byte

func (h Hash) Valid() bool {
	return h[0] == 0 && h[1] == 0 && h[2]&0xfc == 0
}

func (h *Hash) Scan(value interface{}) error {
	if value == nil {
		*h = EmptyHash
		return nil
	}

	v, ok := value.([]byte)
	if !ok {
		return errors.Errorf("cryptopuff: can't convert %T to Hash, expected %T", value, v)
	}

	b, err := hex.DecodeString(string(v))
	if err != nil {
		return errors.Wrap(err, "cryptopuff: failed to hex decode hash")
	}

	if len(b) == 0 {
		*h = EmptyHash
		return nil
	}
	if len(b) != md5.Size {
		return errors.Errorf("cryptopuff: invalid Hash length, expected %v, got %v", md5.Size, len(v))
	}

	copy(h[:], b)
	return nil
}

func (h Hash) Value() (driver.Value, error) {
	if h == EmptyHash {
		return nil, nil
	}
	return hex.EncodeToString(h[:]), nil
}

func (h Hash) MarshalJSON() ([]byte, error) {
	b, err := json.Marshal(hex.EncodeToString(h[:]))
	if err != nil {
		return nil, errors.Wrap(err, "cryptopuff: failed to marshal hash")
	}
	return b, nil
}

func (h *Hash) UnmarshalJSON(data []byte) error {
	var str string
	if err := json.Unmarshal(data, &str); err != nil {
		return errors.Wrap(err, "cryptopuff: failed to unmarshal hash")
	}

	v, err := hex.DecodeString(str)
	if err != nil {
		return errors.Wrap(err, "cryptopuff: failed to hex decode hash")
	}
	if len(v) == 0 {
		*h = EmptyHash
		return nil
	}
	if len(v) != md5.Size {
		return errors.Errorf("cryptopuff: invalid Hash length, expected %v, got %v", md5.Size, len(v))
	}

	copy(h[:], v)
	return nil
}

func (h Hash) String() string {
	return hex.EncodeToString(h[:])
}
