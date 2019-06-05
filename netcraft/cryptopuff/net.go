package cryptopuff

import (
	"net"
	"os/exec"
	"regexp"

	"github.com/pkg/errors"
)

const (
	DefaultPort     = "8080"
	DefaultPassword = "netcraftnetcraftnetcraft"
)

var srcIPRegex = regexp.MustCompile(`src ([0-9]+[.][0-9]+[.][0-9]+[.][0-9]+)`)

func DetectIP() (net.IP, error) {
	b, err := exec.Command("ip", "-o", "route", "get", "8.8.8.8").Output()
	if err != nil {
		return nil, errors.Wrap(err, "cryptopuff: ip route failed")
	}

	m := srcIPRegex.FindSubmatch(b)
	if len(m) != 2 {
		return nil, errors.New("cryptopuff: failed to parse ip route output")
	}

	ip := net.ParseIP(string(m[1]))
	if ip == nil {
		return nil, errors.New("cryptopuff: failed to parse IP")
	}
	return ip, nil
}
