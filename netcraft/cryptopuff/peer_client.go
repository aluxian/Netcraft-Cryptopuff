package cryptopuff

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/pkg/errors"
)

type PeerClient struct {
	client *http.Client
}

type xPeerTransport struct {
	addr string
	next http.RoundTripper
}

func (x xPeerTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	req.Header.Set(headerXPeer, x.addr)
	return x.next.RoundTrip(req)
}

func NewPeerClient(addr string) *PeerClient {
	return &PeerClient{
		client: &http.Client{
			Transport: xPeerTransport{
				addr: addr,
				next: http.DefaultTransport,
			},
			Timeout: Timeout,
		},
	}
}

func (c *PeerClient) Ping(peer string) error {
	resp, err := httpGet(c.client, fmt.Sprintf("http://%v/api/ping", peer))
	if err != nil {
		return errors.Wrap(err, "cryptopuff: GET failed")
	}
	resp.Body.Close()
	return nil
}

func (c *PeerClient) Peers(peer string) ([]string, error) {
	resp, err := httpGet(c.client, fmt.Sprintf("http://%v/api/peers", peer))
	if err != nil {
		return nil, errors.Wrap(err, "cryptopuff: GET failed")
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, errors.Errorf("cryptopuff: invalid status code: %v", resp.StatusCode)
	}

	var peers []string
	if err := json.NewDecoder(resp.Body).Decode(&peers); err != nil {
		return nil, errors.Wrap(err, "cryptopuff: failed to unmarshal JSON")
	}
	return peers, nil
}

func (c *PeerClient) AddPeer(peer string, addr string) error {
	b, err := json.Marshal(addr)
	if err != nil {
		return errors.Wrap(err, "cryptopuff: failed to marshal JSON")
	}

	resp, err := httpPost(c.client, fmt.Sprintf("http://%v/api/peers", peer), contentTypeJSON, bytes.NewReader(b))
	if err != nil {
		return errors.Wrap(err, "cryptopuff: POST failed")
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return errors.Errorf("cryptopuff: invalid status code: %v", resp.StatusCode)
	}

	return nil
}

func (c *PeerClient) Blocks(peer string) ([]Block, error) {
	resp, err := httpGet(c.client, fmt.Sprintf("http://%v/api/blocks", peer))
	if err != nil {
		return nil, errors.Wrap(err, "cryptopuff: GET faield")
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, errors.Errorf("cryptopuff: invalid status code: %v", resp.StatusCode)
	}

	var blocks []Block
	if err := json.NewDecoder(resp.Body).Decode(&blocks); err != nil {
		return nil, errors.Wrap(err, "cryptopuff: failed to unmarshal JSON")
	}
	for i := range blocks {
		if err := blocks[i].UpdateHash(); err != nil {
			return nil, errors.Wrap(err, "cryptopuff: failed to update block hash")
		}
	}
	return blocks, nil
}

func (c *PeerClient) AddBlock(peer string, block *Block) error {
	b, err := json.Marshal(block)
	if err != nil {
		return errors.Wrap(err, "cryptopuff: failed to marshal JSON")
	}

	resp, err := httpPost(c.client, fmt.Sprintf("http://%v/api/blocks", peer), contentTypeJSON, bytes.NewReader(b))
	if err != nil {
		return errors.Wrap(err, "cryptopuff: POST failed")
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return errors.Errorf("cryptopuff: invalid status code: %v", resp.StatusCode)
	}

	return nil
}

func (c *PeerClient) Txs(peer string) ([]SignedTx, error) {
	resp, err := httpGet(c.client, fmt.Sprintf("http://%v/api/txs", peer))
	if err != nil {
		return nil, errors.Wrap(err, "cryptopuff: GET failed")
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, errors.Errorf("cryptopuff: invalid status code: %v", resp.StatusCode)
	}

	var stxs []SignedTx
	if err := json.NewDecoder(resp.Body).Decode(&stxs); err != nil {
		return nil, errors.Wrap(err, "cryptopuff: failed to unmarshal JSON")
	}
	for i := range stxs {
		if err := stxs[i].UpdateHash(); err != nil {
			return nil, errors.Wrap(err, "cryptopuff: failed to update transaction hash")
		}
	}
	return stxs, nil
}

func (c *PeerClient) AddTx(peer string, tx *SignedTx) error {
	b, err := json.Marshal(tx)
	if err != nil {
		return errors.Wrap(err, "cryptopuff: failed to marshal JSON")
	}

	resp, err := httpPost(c.client, fmt.Sprintf("http://%v/api/txs", peer), contentTypeJSON, bytes.NewReader(b))
	if err != nil {
		return errors.Wrap(err, "cryptopuff: POST failed")
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return errors.Errorf("cryptopuff: invalid status code: %v", resp.StatusCode)
	}

	return nil
}
