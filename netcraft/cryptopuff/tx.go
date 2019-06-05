package cryptopuff

import (
	"crypto"
	"crypto/md5"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"

	"github.com/JohnCGriffin/overflow"
	"github.com/pkg/errors"
)

type Tx struct {
	TxOutput
	Source Address
	Fee    int64
}

type TxOutput struct {
	Destination Address
	Amount      int64
}

func (t Tx) ValidAmounts() error {
	if t.Fee < 0 {
		return errors.New("cryptopuff: negative fee")
	}
	if t.Amount <= 0 {
		return errors.New("cryptopuff: negative or zero amount")
	}
	_, ok := overflow.Add64(t.Fee, t.Amount)
	if !ok {
		return errors.New("cryptopuff: fee plus amount overflows")
	}
	return nil
}

func (t Tx) RequiredBalance() int64 {
	return t.Fee + t.Amount
}

func (t Tx) Sign(k *rsa.PrivateKey) (*SignedTx, error) {
	b, err := json.Marshal(t)
	if err != nil {
		return nil, errors.Wrap(err, "cryptopuff: failed to marshal JSON")
	}
	hash := md5.Sum(b)

	sig, err := rsa.SignPSS(rand.Reader, k, crypto.MD5, hash[:], nil)
	if err != nil {
		return nil, errors.Wrap(err, "cryptopuff: failed to sign transaction")
	}

	var id TxID
	if _, err := rand.Read(id[:]); err != nil {
		return nil, errors.Wrap(err, "cryptopuff: failed to generate TxID")
	}

	stx := &SignedTx{
		Tx:        t,
		ID:        id,
		Signature: sig,
		PublicKey: x509.MarshalPKCS1PublicKey(&k.PublicKey),
	}
	if err := stx.UpdateHash(); err != nil {
		return nil, errors.Wrap(err, "cryptopuff: failed to update transaction hash")
	}
	return stx, nil
}

const TxIDSize = 16

type TxID [TxIDSize]byte

func (t TxID) MarshalJSON() ([]byte, error) {
	b, err := json.Marshal(hex.EncodeToString(t[:]))
	if err != nil {
		return nil, errors.Wrap(err, "cryptopuff: failed to marshal TxID")
	}
	return b, nil
}

func (t *TxID) UnmarshalJSON(data []byte) error {
	var str string
	if err := json.Unmarshal(data, &str); err != nil {
		return errors.Wrap(err, "cryptopuff: failed to unmarshal TxID")
	}

	v, err := hex.DecodeString(str)
	if err != nil {
		return errors.Wrap(err, "cryptopuff: failed to hex decode TxID")
	}
	if len(v) != TxIDSize {
		return errors.Errorf("cryptopuff: invalid TxID length, expected %v, got %v", TxIDSize, len(v))
	}

	copy(t[:], v)
	return nil
}

func (t TxID) String() string {
	return hex.EncodeToString(t[:])
}

type SignedTx struct {
	Tx
	Hash      Hash `json:"-"`
	ID        TxID
	Signature []byte
	PublicKey []byte
}

func (s *SignedTx) UpdateHash() error {
	raw, err := json.Marshal(s)
	if err != nil {
		return errors.Wrap(err, "cryptopuff: failed to marshal JSON")
	}
	s.Hash = Hash(md5.Sum(raw))
	return nil
}

func (s SignedTx) ValidSignature() error {
	k, err := x509.ParsePKCS1PublicKey(s.PublicKey)
	if err != nil {
		return errors.Wrap(err, "cryptopuff: failed to parse public key")
	}

	addressV1 := AddressFromKey(V1, k)
	addressV2 := AddressFromKey(V2, k)
	if !addressV1.Equal(s.Tx.Source) && !addressV2.Equal(s.Tx.Source) {
		return errors.New("cryptopuff: address doesn't match public key")
	}

	b, err := json.Marshal(s.Tx)
	if err != nil {
		return errors.Wrap(err, "cryptopuff: failed to marshal JSON")
	}
	hash := md5.Sum(b)

	if err := rsa.VerifyPSS(k, crypto.MD5, hash[:], s.Signature, nil); err != nil {
		return errors.Wrap(err, "cryptopuff: invalid signature")
	}
	return nil
}

func (s SignedTx) Valid() error {
	if err := s.ValidAmounts(); err != nil {
		return InvalidBlockError{Message: "cryptopuff: invalid amounts", Cause: err}
	}

	if err := s.ValidSignature(); err != nil {
		return InvalidBlockError{Message: "cryptopuff: invalid signature", Cause: err}
	}

	return nil
}

type PersonalTx struct {
	SignedTx
	Included bool
	Height   int64
}
