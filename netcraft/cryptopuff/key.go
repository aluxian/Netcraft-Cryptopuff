package cryptopuff

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"math/rand"

	"github.com/pkg/errors"
)

const (
	DefaultKeyLength  = 256
	privateKeyPemType = "RSA PRIVATE KEY"
)

func GenerateKey(bits int, seed int64) (*rsa.PrivateKey, error) {
	r := rand.New(rand.NewSource(seed))
	return RSAGenerateKey(r, bits)
}

func EncodePrivateKeyPEM(k *rsa.PrivateKey) []byte {
	return pem.EncodeToMemory(&pem.Block{
		Type:  privateKeyPemType,
		Bytes: x509.MarshalPKCS1PrivateKey(k),
	})
}

func DecodePrivateKeyPEM(b []byte) (*rsa.PrivateKey, error) {
	block, _ := pem.Decode(b)
	if block == nil {
		return nil, errors.New("cryptopuff: no PEM block found")
	}

	if block.Type != privateKeyPemType {
		return nil, errors.New("cryptopuff: invalid PEM block type")
	}

	return x509.ParsePKCS1PrivateKey(block.Bytes)
}
