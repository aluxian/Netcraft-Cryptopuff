package cryptopuff

import (
	"crypto/md5"
	"encoding/binary"
	"encoding/json"
	"fmt"

	"github.com/pkg/errors"
)

var GenesisBlock = &Block{Nonce: 39611433}

func init() {
	if err := GenesisBlock.UpdateHash(); err != nil {
		panic(err)
	}
}

const (
	MaxBlockReward          = 1000
	MaxTransactionsPerBlock = 100
)

type Block struct {
	Hash         Hash `json:"-"`
	PreviousHash Hash
	Height       int64
	Nonce        int64
	RewardOutput TxOutput
	Transactions []SignedTx
}

func NewBlock(previous *Block, nonce int64, addr Address, blockReward int64, stxs []SignedTx) (*Block, error) {
	b := &Block{
		PreviousHash: previous.Hash,
		Height:       previous.Height + 1,
		Nonce:        nonce,
		RewardOutput: TxOutput{
			Destination: addr,
			Amount:      blockReward,
		},
		Transactions: stxs,
	}
	if err := b.UpdateHash(); err != nil {
		return nil, errors.Wrap(err, "cryptopuff: failed to update block hash")
	}
	return b, nil
}

func DecodeBlock(in []byte) (*Block, error) {
	var b Block
	if err := json.Unmarshal(in, &b); err != nil {
		return nil, errors.Wrap(err, "cryptopuff: failed to unmarshal block")
	}
	if err := b.UpdateHash(); err != nil {
		return nil, errors.Wrap(err, "cryptopuff: failed to update block hash")
	}
	return &b, nil
}

func (b *Block) UpdateHash() error {
	raw, err := json.Marshal(b.Transactions)
	if err != nil {
		return errors.Wrap(err, "cryptopuff: failed to marshal transactions")
	}
	txListHash := Hash(md5.Sum(raw))

	h := md5.New()
	h.Write(b.PreviousHash[:])
	binary.Write(h, binary.BigEndian, b.Height)
	binary.Write(h, binary.BigEndian, b.Nonce)
	binary.Write(h, binary.BigEndian, int64(len(b.RewardOutput.Destination)))
	h.Write(b.RewardOutput.Destination)
	binary.Write(h, binary.BigEndian, b.RewardOutput.Amount)
	h.Write(txListHash[:])
	copy(b.Hash[:], h.Sum(nil))

	for i := range b.Transactions {
		if err := b.Transactions[i].UpdateHash(); err != nil {
			return errors.Wrap(err, "cryptopuff: failed to update transaction hash")
		}
	}

	return nil
}

func (b *Block) Valid(previous *Block) error {
	if b.PreviousHash != previous.Hash {
		return InvalidBlockError{Message: fmt.Sprintf("cryptopuff: previous hash mismatch (expected %v, got %v)", previous.Height, b.PreviousHash)}
	}

	if b.Height != previous.Height+1 {
		return InvalidBlockError{Message: fmt.Sprintf("cryptopuff: height mismatch (expected %v, got %v)", previous.Height+1, b.Height)}
	}

	if !b.Hash.Valid() {
		return InvalidBlockError{Message: "cryptopuff: hash doesn't meet difficulty requirement"}
	}

	if b.RewardOutput.Amount < 0 || b.RewardOutput.Amount > MaxBlockReward {
		return InvalidBlockError{Message: "cryptopuff: reward amount negative or greater than maximum"}
	}

	if len(b.Transactions) > MaxTransactionsPerBlock {
		return InvalidBlockError{Message: "cryptopuff: number of transactions greater than maximum"}
	}

	for _, t := range b.Transactions {
		if err := t.Valid(); err != nil {
			return err
		}
	}

	return nil
}
