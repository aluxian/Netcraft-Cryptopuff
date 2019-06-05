package main

import (
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"net"
	"os"
	"strconv"
	"text/tabwriter"
	"time"

	"gitlab.netcraft.com/netcraft/recruitment/cryptopuff"
	"golang.org/x/text/language"
	"golang.org/x/text/message"
)

var englishPrinter = message.NewPrinter(language.BritishEnglish)

func main() {
	defaultAddr := net.JoinHostPort("localhost", cryptopuff.DefaultPort)

	var (
		addr     = flag.String("addr", defaultAddr, "address of the local node")
		password = flag.String("password", cryptopuff.DefaultPassword, "password for accessing the local node's wallet")
		bits     = flag.Int("bits", cryptopuff.DefaultKeyLength, "RSA key length in bits")
		seed     = flag.Int64("seed", time.Now().Unix(), "random number generator seed")
		v2       = flag.Bool("v2", false, "use new v2 address format")
	)
	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "Usage of %s:\n", os.Args[0])
		flag.PrintDefaults()
		fmt.Fprintln(os.Stderr, "Subcommands:")
		fmt.Fprintln(os.Stderr, "  genkey")
		fmt.Fprintln(os.Stderr, "    generates a new private key and prints its address")
		fmt.Fprintln(os.Stderr, "  importkey <file>")
		fmt.Fprintln(os.Stderr, "    imports an existing private key from <file> and prints its address")
		fmt.Fprintln(os.Stderr, "  exportkey <address>")
		fmt.Fprintln(os.Stderr, "    exports the private key for <address> and prints it")
		fmt.Fprintln(os.Stderr, "  setmineraddr <address>")
		fmt.Fprintln(os.Stderr, "    sets the block reward destination address for blocks mined by this node")
		fmt.Fprintln(os.Stderr, "  balance")
		fmt.Fprintln(os.Stderr, "    prints the balance of each address in your wallet")
		fmt.Fprintln(os.Stderr, "  txs")
		fmt.Fprintln(os.Stderr, "    prints all transactions to or from addresses in your wallet")
		fmt.Fprintln(os.Stderr, "  send <source> <destination> <amount> <fee>")
		fmt.Fprintln(os.Stderr, "    sends <amount> coins from <source> to <destination> with a miner fee of <fee>")
		fmt.Fprintln(os.Stdout, "  peers")
		fmt.Fprintln(os.Stdout, "    prints all peers connected to this node")
		os.Exit(1)
	}
	flag.Parse()

	if flag.NArg() < 1 {
		flag.Usage()
	}

	client := cryptopuff.NewRPCClient(*addr, *password)

	var version cryptopuff.Version
	if *v2 {
		version = cryptopuff.V2
	} else {
		version = cryptopuff.V1
	}

	switch flag.Arg(0) {
	case "genkey":
		if err := generateKey(client, version, *bits, *seed); err != nil {
			log.Fatalln(err)
		}
	case "importkey":
		var path string
		if flag.NArg() < 1 {
			flag.Usage()
		} else if flag.NArg() < 2 {
			path = "/dev/stdin"
		} else {
			path = flag.Arg(1)
		}

		if err := importKey(client, path, version); err != nil {
			log.Fatalln(err)
		}
	case "exportkey":
		if flag.NArg() < 2 {
			flag.Usage()
		}

		if err := exportKey(client, flag.Arg(1)); err != nil {
			log.Fatalln(err)
		}
	case "setmineraddr":
		if flag.NArg() < 2 {
			flag.Usage()
		}

		if err := setMinerAddress(client, flag.Arg(1)); err != nil {
			log.Fatalln(err)
		}
	case "balance":
		if err := balance(client); err != nil {
			log.Fatalln(err)
		}
	case "txs":
		if err := txs(client); err != nil {
			log.Fatalln(err)
		}
	case "send":
		if flag.NArg() < 4 {
			flag.Usage()
		}

		if err := send(client, flag.Arg(1), flag.Arg(2), flag.Arg(3), flag.Arg(4)); err != nil {
			log.Fatalln(err)
		}
	case "peers":
		if err := peers(client); err != nil {
			log.Fatalln(err)
		}
	default:
		flag.Usage()
	}
}

func generateKey(client *cryptopuff.RPCClient, v cryptopuff.Version, bits int, seed int64) error {
	k, err := cryptopuff.GenerateKey(bits, seed)
	if err != nil {
		return err
	}

	addr, err := client.AddKey(k, v)
	if err != nil {
		return err
	}

	fmt.Println(addr)
	return nil
}

func importKey(client *cryptopuff.RPCClient, file string, v cryptopuff.Version) error {
	b, err := ioutil.ReadFile(file)
	if err != nil {
		return err
	}

	k, err := cryptopuff.DecodePrivateKeyPEM(b)
	if err != nil {
		return err
	}

	addr, err := client.AddKey(k, v)
	if err != nil {
		return err
	}

	fmt.Println(addr)
	return nil
}

func exportKey(client *cryptopuff.RPCClient, addrStr string) error {
	addr, err := cryptopuff.AddressFromString(addrStr)
	if err != nil {
		return err
	}

	key, err := client.Key(addr)
	if err != nil {
		return err
	}

	os.Stdout.Write(cryptopuff.EncodePrivateKeyPEM(key))
	return nil
}

func setMinerAddress(client *cryptopuff.RPCClient, addrStr string) error {
	addr, err := cryptopuff.AddressFromString(addrStr)
	if err != nil {
		return err
	}

	// XXX(gpe): somewhat hacky way to check that the address is one we know
	// the key for, to prevent people losing out due to typos
	if _, err := client.Key(addr); err != nil {
		return err
	}

	return client.SetMinerAddress(addr)
}

func balance(client *cryptopuff.RPCClient) error {
	addrs, err := client.Addresses()
	if err != nil {
		return err
	}

	w := tabwriter.NewWriter(os.Stdout, 0, 0, 8, ' ', 0)
	fmt.Fprintln(w, "Address\tBalance")
	fmt.Fprintln(w, "--------\t--------")

	var total int64
	for _, addr := range addrs {
		englishPrinter.Fprintf(w, "%v\t%v\n", addr.Address, addr.Balance)
		total += addr.Balance
	}

	fmt.Fprintln(w, "--------\t--------")
	englishPrinter.Fprintf(w, "Total:\t%v\n", total)
	w.Flush()
	return nil
}

func txs(client *cryptopuff.RPCClient) error {
	txs, err := client.MyTxs()
	if err != nil {
		return err
	}

	w := tabwriter.NewWriter(os.Stdout, 0, 0, 8, ' ', 0)
	fmt.Fprintln(w, "Source\tDestination\tAmount\tFee\tIncluded at block height")
	fmt.Fprintln(w, "--------\t--------\t--------\t--------\t--------")

	for _, tx := range txs {
		var height string
		if tx.Included {
			height = strconv.FormatInt(tx.Height, 10)
		} else {
			height = "Pending"
		}
		englishPrinter.Fprintf(w, "%v\t%v\t%v\t%v\t%v\n", tx.Source, tx.Destination, tx.Amount, tx.Fee, height)
	}

	w.Flush()
	return nil
}

func send(client *cryptopuff.RPCClient, srcStr, destStr, amountStr, feeStr string) error {
	src, err := cryptopuff.AddressFromString(srcStr)
	if err != nil {
		return err
	}

	dest, err := cryptopuff.AddressFromString(destStr)
	if err != nil {
		return err
	}

	amount, err := strconv.ParseInt(amountStr, 10, 64)
	if err != nil {
		return err
	}

	fee, err := strconv.ParseInt(feeStr, 10, 64)
	if err != nil {
		return err
	}

	stx, err := client.SignTx(&cryptopuff.Tx{
		Source:   src,
		TxOutput: cryptopuff.TxOutput{Destination: dest, Amount: amount},
		Fee:      fee,
	})
	if err != nil {
		return err
	}
	return client.BroadcastTx(stx)
}

func peers(client *cryptopuff.RPCClient) error {
	peers, err := client.Peers()
	if err != nil {
		return err
	}

	for _, peer := range peers {
		fmt.Println(peer)
	}
	return nil
}
