package cryptopuff

import (
	"bytes"
	"crypto/md5"
	"crypto/rsa"
	"crypto/x509"
	"database/sql/driver"
	"encoding/base64"

	"github.com/pkg/errors"
)

type Version int

const (
	V1 Version = iota
	V2
)

const DefaultVersion = V1

type Address []byte

func AddressFromString(str string) (Address, error) {
	b, err := base64.StdEncoding.DecodeString(str)
	if err != nil {
		return nil, err
	}
	return Address(b), nil
}

func AddressFromKey(version Version, k *rsa.PublicKey) Address {
	hash := md5.Sum(x509.MarshalPKCS1PublicKey(k))
	if version == V1 {
		return Address(hash[:2])
	}
	return Address(hash[:])
}

func (a *Address) Scan(value interface{}) error {
	v, ok := value.([]byte)
	if !ok {
		return errors.Errorf("cryptopuff: can't convert %T to Address, expected %T", value, v)
	}

	b, err := base64.StdEncoding.DecodeString(string(v))
	if err != nil {
		return errors.Wrap(err, "cryptopuff: failed to base64 decode address")
	}

	*a = b
	return nil
}

func (a Address) Value() (driver.Value, error) {
	return base64.StdEncoding.EncodeToString(a), nil
}

func (a Address) Equal(b Address) bool {
	return bytes.Equal(a, b)
}

func (a Address) String() string {
	return base64.StdEncoding.EncodeToString(a)
}

type AddressState struct {
	Address   Address
	PublicKey []byte
	Balance   int64
}
