package cryptopuff

import (
	"bytes"
	"crypto/rsa"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"

	"github.com/pkg/errors"
)

type RPCClient struct {
	client *http.Client
	addr   string
}

type basicAuthTransport struct {
	password string
	next     http.RoundTripper
}

func (b basicAuthTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	req.SetBasicAuth("", b.password)
	return b.next.RoundTrip(req)
}

func NewRPCClient(addr, password string) *RPCClient {
	return &RPCClient{
		client: &http.Client{
			Transport: basicAuthTransport{
				password: password,
				next:     http.DefaultTransport,
			},
			Timeout: Timeout,
		},
		addr: addr,
	}
}

func (c *RPCClient) Peers() ([]string, error) {
	resp, err := httpGet(c.client, fmt.Sprintf("http://%v/api/peers", c.addr))
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

func (c *RPCClient) Addresses() ([]AddressState, error) {
	resp, err := httpGet(c.client, fmt.Sprintf("http://%v/api/addresses", c.addr))
	if err != nil {
		return nil, errors.Wrap(err, "cryptopuff: GET failed")
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, errors.Errorf("cryptopuff: invalid status code: %v", resp.StatusCode)
	}

	var addrs []AddressState
	if err := json.NewDecoder(resp.Body).Decode(&addrs); err != nil {
		return nil, errors.Wrap(err, "cryptopuff: failed to unmarshal JSON")
	}
	return addrs, nil
}

func (c *RPCClient) MyTxs() ([]PersonalTx, error) {
	resp, err := httpGet(c.client, fmt.Sprintf("http://%v/api/txs/mine", c.addr))
	if err != nil {
		return nil, errors.Wrap(err, "cryptopuff: GET failed")
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, errors.Errorf("cryptopuff: invalid status code: %v", resp.StatusCode)
	}

	var txs []PersonalTx
	if err := json.NewDecoder(resp.Body).Decode(&txs); err != nil {
		return nil, errors.Wrap(err, "cryptopuff: failed to unmarshal JSON")
	}
	for i := range txs {
		if err := txs[i].UpdateHash(); err != nil {
			return nil, errors.Wrap(err, "cryptopuff: failed to update transaction hash")
		}
	}
	return txs, nil
}

func (c *RPCClient) AddKey(k *rsa.PrivateKey, v Version) (Address, error) {
	b := EncodePrivateKeyPEM(k)

	resp, err := httpPost(c.client, fmt.Sprintf("http://%v/api/keys?version=%v", c.addr, v), contentTypePEM, bytes.NewReader(b))
	if err != nil {
		return nil, errors.Wrap(err, "cryptopuff: POST failed")
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, errors.Errorf("cryptopuff: invalid status code: %v", resp.StatusCode)
	}

	var a Address
	if err := json.NewDecoder(resp.Body).Decode(&a); err != nil {
		return nil, errors.Wrap(err, "cryptopuff: failed to unmarshal JSON")
	}
	return a, nil
}

func (c *RPCClient) Key(addr Address) (*rsa.PrivateKey, error) {
	resp, err := httpGet(c.client, fmt.Sprintf("http://%v/api/keys/%v", c.addr, url.PathEscape(addr.String())))
	if err != nil {
		return nil, errors.Wrap(err, "cryptopuff: GET failed")
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, errors.Errorf("cryptopuff: invalid status code: %v", resp.StatusCode)
	}

	b, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, errors.Wrap(err, "cryptopuff: failed to read response body")
	}

	k, err := DecodePrivateKeyPEM(b)
	if err != nil {
		return nil, errors.Wrap(err, "cryptopuff: failed to decode private key")
	}
	return k, nil
}

func (c *RPCClient) SetMinerAddress(addr Address) error {
	b, err := json.Marshal(addr)
	if err != nil {
		return errors.Wrap(err, "cryptopuff: failed to marshal JSON")
	}

	resp, err := httpPost(c.client, fmt.Sprintf("http://%v/api/addresses/miner", c.addr), contentTypeJSON, bytes.NewReader(b))
	if err != nil {
		return errors.Wrap(err, "cryptopuff: POST failed")
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return errors.Errorf("cryptopuff: invalid status code: %v", resp.StatusCode)
	}

	return nil
}

func (c *RPCClient) SignTx(tx *Tx) (*SignedTx, error) {
	b, err := json.Marshal(tx)
	if err != nil {
		return nil, errors.Wrap(err, "cryptopuff: failed to marshal JSON")
	}

	resp, err := httpPost(c.client, fmt.Sprintf("http://%v/api/txs/sign", c.addr), contentTypeJSON, bytes.NewReader(b))
	if err != nil {
		return nil, errors.Wrap(err, "cryptopuff: POST failed")
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, errors.Errorf("cryptopuff: invalid status code: %v", resp.StatusCode)
	}

	var stx SignedTx
	if err := json.NewDecoder(resp.Body).Decode(&stx); err != nil {
		return nil, errors.Wrap(err, "cryptopuff: failed to unmarshal JSON")
	}
	if err := stx.UpdateHash(); err != nil {
		return nil, errors.Wrap(err, "cryptopuff: failed to update transaction hash")
	}
	return &stx, nil
}

func (c *RPCClient) BroadcastTx(stx *SignedTx) error {
	b, err := json.Marshal(stx)
	if err != nil {
		return errors.Wrap(err, "cryptopuff: failed to marshal JSON")
	}

	resp, err := httpPost(c.client, fmt.Sprintf("http://%v/api/txs/broadcast", c.addr), contentTypeJSON, bytes.NewReader(b))
	if err != nil {
		return errors.Wrap(err, "crypotpuff: POST failed")
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return errors.Errorf("cryptopuff: invalid status code: %v", resp.StatusCode)
	}

	return nil
}
