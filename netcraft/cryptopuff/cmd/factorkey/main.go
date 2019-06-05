package main

import (
	"bufio"
	"bytes"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"fmt"
	"io/ioutil"
	"log"
	"math/big"
	"os"
	"os/exec"
	"regexp"
	"strings"

	"github.com/pkg/errors"
	"gitlab.netcraft.com/netcraft/recruitment/cryptopuff"
)

var (
	factorRegex = regexp.MustCompile(`P\d+ = (\d+)`)
	one         = big.NewInt(1)
)

func main() {
	r := base64.NewDecoder(base64.StdEncoding, os.Stdin)

	b, err := ioutil.ReadAll(r)
	if err != nil {
		log.Fatalln(err)
	}

	publicKey, err := x509.ParsePKCS1PublicKey(b)
	if err != nil {
		log.Fatalln(err)
	}

	privateKey, err := factorRSA(publicKey)
	if err != nil {
		log.Fatalln(err)
	}

	os.Stdout.Write(cryptopuff.EncodePrivateKeyPEM(privateKey))
}

func factorRSA(k *rsa.PublicKey) (*rsa.PrivateKey, error) {
	p, q, err := factor(k.N)
	if err != nil {
		return nil, err
	}

	var pMinus1 big.Int
	pMinus1.Sub(p, one)

	var qMinus1 big.Int
	qMinus1.Sub(q, one)

	var phi big.Int
	phi.Mul(&pMinus1, &qMinus1)

	var d big.Int
	d.ModInverse(big.NewInt(int64(k.E)), &phi)

	return &rsa.PrivateKey{
		PublicKey: *k,
		D:         &d,
		Primes:    []*big.Int{p, q},
	}, nil
}

func factor(n *big.Int) (*big.Int, *big.Int, error) {
	cmd := exec.Command("yafu")
	cmd.Stdin = strings.NewReader(fmt.Sprintf("factor(%v)", n))

	b, err := cmd.Output()
	if err != nil {
		return nil, nil, errors.Wrap(err, "factorkey: yafu failed")
	}

	var factors []big.Int

	s := bufio.NewScanner(bytes.NewReader(b))
	for s.Scan() {
		m := factorRegex.FindStringSubmatch(s.Text())
		if len(m) != 2 {
			continue
		}

		var f big.Int
		if _, ok := f.SetString(m[1], 10); !ok {
			return nil, nil, errors.New("factorkey: failed to set big.Int")
		}
		factors = append(factors, f)
	}
	if err := s.Err(); err != nil {
		return nil, nil, err
	}

	if len(factors) != 2 {
		return nil, nil, errors.New("factorkey: failed to find two factors in yafu output")
	}
	return &factors[0], &factors[1], nil
}
