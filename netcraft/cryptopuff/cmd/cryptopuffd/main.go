package main

import (
	"flag"
	"fmt"
	"log"
	"net"
	"os/user"
	"strings"

	"gitlab.netcraft.com/netcraft/recruitment/cryptopuff"
)

func main() {
	u, err := user.Current()
	if err != nil {
		log.Fatalln(err)
	}

	ip, err := cryptopuff.DetectIP()
	if err != nil {
		log.Fatalln(err)
	}

	defaultAddr := net.JoinHostPort("", cryptopuff.DefaultPort)
	defaultExtAddr := net.JoinHostPort(ip.String(), cryptopuff.DefaultPort)
	defaultDSN := fmt.Sprintf("%v/cryptopuff.sqlite3", u.HomeDir)
	defaultPeers := net.JoinHostPort("cryptopuff.netcraft.com", cryptopuff.DefaultPort)

	var (
		addr        = flag.String("addr", defaultAddr, "address to bind to (changing this will break the scoring system)")
		extAddr     = flag.String("extAddr", defaultExtAddr, "address peers can use to reach this node (changing this will break the scoring system)")
		dsn         = flag.String("db", defaultDSN, "path to the database file (do not delete this file, it contains your private keys)")
		peers       = flag.String("peers", defaultPeers, "comma-separated list of well-known peer addresses")
		password    = flag.String("password", cryptopuff.DefaultPassword, "password for restricting access to this node's wallet")
		blockReward = flag.Int64("blockReward", 100, "block reward to claim in blocks mined by this node")
	)
	flag.Parse()

	db, err := cryptopuff.OpenDB(*dsn)
	if err != nil {
		log.Fatalln(err)
	}
	defer db.Close()

	server := cryptopuff.NewServer(*addr, *extAddr, *password, *blockReward, split(*peers, ","), db)
	if err := server.Serve(); err != nil {
		log.Fatalln(err)
	}
}

func split(s, sep string) []string {
	if s == "" {
		return nil
	}
	return strings.Split(s, sep)
}
