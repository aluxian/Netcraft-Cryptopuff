package cryptopuff

import (
	"bufio"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/pkg/errors"
)

const (
	contentTypeJSON = "application/json"
	contentTypePEM  = "application/x-pem-file"

	Timeout = 1 * time.Minute
)

var (
	headerContentType     = http.CanonicalHeaderKey("Content-Type")
	headerWWWAuthenticate = http.CanonicalHeaderKey("WWW-Authenticate")
	headerXPeer           = http.CanonicalHeaderKey("X-Peer")
)

func httpGet(c *http.Client, url string) (*http.Response, error) {
	resp, err := c.Get(url)
	if err != nil {
		return nil, err
	}

	if resp.StatusCode != http.StatusOK {
		defer resp.Body.Close()

		line, err := bufio.NewReader(resp.Body).ReadString('\n')
		if err != nil {
			return nil, errors.Wrap(err, "cryptopuff: failed to read first line of non-200 response")
		}
		line = strings.TrimRight(line, "\n")

		return nil, errors.Errorf("cryptopuff: invalid status code %v: %v", resp.StatusCode, line)
	}

	return resp, nil
}

func httpPost(c *http.Client, url string, contentType string, body io.Reader) (*http.Response, error) {
	resp, err := c.Post(url, contentType, body)
	if err != nil {
		return nil, err
	}

	if resp.StatusCode != http.StatusOK {
		defer resp.Body.Close()

		line, err := bufio.NewReader(resp.Body).ReadString('\n')
		if err != nil {
			return nil, errors.Wrap(err, "cryptopuff: failed to read first line of non-200 response")
		}
		line = strings.TrimRight(line, "\n")

		return nil, errors.Errorf("cryptopuff: invalid status code %v: %v", resp.StatusCode, line)
	}

	return resp, nil
}
