package cryptopuff

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"math/rand"
	"net/http"
	"net/url"
	"runtime"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"github.com/go-chi/chi"
	"github.com/go-chi/chi/middleware"
	"github.com/pkg/errors"
)

type Server struct {
	addr, extAddr    string
	password         string
	blockReward      int64
	wellKnownPeers   map[string]struct{}
	client           *PeerClient
	router           chi.Router
	db               *DB
	bestBlockVersion uint64
	hashesPerSec     uint64
}

func NewServer(addr, extAddr, password string, blockReward int64, peers []string, db *DB) *Server {
	server := &Server{
		addr:           addr,
		extAddr:        strings.ToLower(extAddr),
		password:       password,
		blockReward:    blockReward,
		wellKnownPeers: createWellKnownPeers(peers),
		client:         NewPeerClient(extAddr),
		router:         chi.NewRouter(),
		db:             db,
	}
	server.routes()
	return server
}

func createWellKnownPeers(peers []string) map[string]struct{} {
	m := make(map[string]struct{})
	for _, peer := range peers {
		m[strings.ToLower(peer)] = struct{}{}
	}
	return m
}

func (s *Server) routes() {
	s.router.Use(middleware.GetHead)

	s.router.Get("/api/ping", s.ping)
	s.router.Get("/api/peers", s.peers)
	s.router.Post("/api/peers", s.addPeer)
	s.router.Get("/api/blocks", s.blocks)
	s.router.Post("/api/blocks", s.addBlock)
	s.router.Get("/api/txs", s.txs)
	s.router.Post("/api/txs", s.addTx)
	s.router.Get("/api/addresses", s.addresses)
	s.router.Get("/api/addresses/proofs", s.addressProofs)

	s.router.Group(func(r chi.Router) {
		r.Use(s.checkPassword)

		r.Post("/api/addresses/miner", s.setMinerAddress)
		r.Post("/api/keys", s.addKey)
		r.Get("/api/keys/{address}", s.key)
		r.Get("/api/txs/mine", s.myTxs)
		r.Post("/api/txs/sign", s.signTx)
		r.Post("/api/txs/broadcast", s.broadcastTx)
	})
}

func (s *Server) checkPassword(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, password, ok := r.BasicAuth()
		if !ok || password != s.password {
			w.Header().Set(headerWWWAuthenticate, "Basic realm=\"cryptopuff\"")
			http.Error(w, "cryptopuff: invalid password", http.StatusUnauthorized)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func (s *Server) ping(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusOK)
}

func (s *Server) peers(w http.ResponseWriter, r *http.Request) {
	peers, err := s.db.Peers()
	if err != nil {
		http.Error(w, fmt.Sprintf("cryptopuff: failed to select peers: %v", err), http.StatusInternalServerError)
		return
	}

	w.Header().Set(headerContentType, contentTypeJSON)
	if err := json.NewEncoder(w).Encode(peers); err != nil {
		http.Error(w, fmt.Sprintf("cryptopuff: failed to marshal JSON: %v", err), http.StatusInternalServerError)
		return
	}
}

func (s *Server) fetchPeers(peer string) error {
	peers, err := s.client.Peers(peer)
	if err != nil {
		return errors.Wrap(err, "cryptopuff: failed to select peers")
	}

	for _, peer := range peers {
		if err := s.validateAndAddPeer(peer); err != nil {
			return errors.Wrap(err, "cryptopuff: failed to add peer")
		}
	}

	return nil
}

func (s *Server) addPeer(w http.ResponseWriter, r *http.Request) {
	var peer string
	if err := json.NewDecoder(r.Body).Decode(&peer); err != nil {
		http.Error(w, fmt.Sprintf("cryptopuff: failed to unmarshal JSON: %v", err), http.StatusBadRequest)
		return
	}

	if err := s.validateAndAddPeer(peer); err != nil {
		http.Error(w, fmt.Sprintf("cryptopuff: failed to add peer: %v", err), http.StatusBadRequest)
		return
	}
}

func (s *Server) validateAndAddPeer(peer string) error {
	peer = strings.ToLower(peer)
	if peer == s.extAddr {
		return nil
	}

	exists, err := s.db.PeerExists(peer)
	if err != nil {
		return errors.Wrap(err, "cryptopuff: failed to check if peer exists")
	}
	if exists {
		return nil
	}

	go func() {
		if err := s.client.Ping(peer); err != nil {
			log.Printf("ignoring peer %v, ping failed: %v\n", peer, err)
			return
		}

		created, err := s.db.AddPeer(peer)
		if err != nil {
			log.Printf("failed to add peer to database: %v\n", err)
			return
		}
		if !created {
			return
		}

		peers, err := s.db.Peers()
		if err != nil {
			log.Printf("failed to select peers: %v\n", err)
			return
		}
		for _, p := range peers {
			if p == peer {
				continue
			}

			p := p
			go func() {
				if err := s.client.AddPeer(p, peer); err != nil {
					log.Printf("failed to notify peer %v about new peer %v: %v\n", p, peer, err)
				}
			}()
		}

		if err := s.fullPeerSync(peer); err != nil {
			log.Printf("full peer sync with new peer failed: %v\n", err)
		}
	}()
	return nil
}

func (s *Server) fullPeerSync(peer string) error {
	if err := s.client.AddPeer(peer, s.extAddr); err != nil {
		return errors.Wrapf(err, "cryptopuff: failed to notify peer %v about ourselves", peer)
	}

	if err := s.fetchPeers(peer); err != nil {
		return errors.Wrapf(err, "cryptopuff: failed to fetch peers from %v", peer)
	}

	if err := s.fetchBlocks(peer); err != nil {
		return errors.Wrapf(err, "cryptopuff: failed to fetch blocks from %v", peer)
	}

	if err := s.fetchTxs(peer); err != nil {
		return errors.Wrapf(err, "cryptopuff: failed to fetch transactions from %v", peer)
	}

	return nil
}

func (s *Server) blocks(w http.ResponseWriter, r *http.Request) {
	blocks, err := s.db.Blocks()
	if err != nil {
		http.Error(w, fmt.Sprintf("cryptopuff: failed to select blocks: %v", err), http.StatusInternalServerError)
		return
	}

	w.Header().Set(headerContentType, contentTypeJSON)
	if err := json.NewEncoder(w).Encode(blocks); err != nil {
		http.Error(w, fmt.Sprintf("cryptopuff: failed to marshal JSON: %v", err), http.StatusInternalServerError)
		return
	}
}

func (s *Server) fetchBlocks(peer string) error {
	blocks, err := s.client.Blocks(peer)
	if err != nil {
		return errors.Wrap(err, "cryptopuff: failed to download blocks")
	}

	if err := s.db.AddBlocks(blocks); err != nil {
		return errors.Wrap(err, "cryptopuff: failed to add blocks to database")
	}

	atomic.AddUint64(&s.bestBlockVersion, 1)
	return nil
}

func (s *Server) addBlock(w http.ResponseWriter, r *http.Request) {
	var b Block
	if err := json.NewDecoder(r.Body).Decode(&b); err != nil {
		http.Error(w, fmt.Sprintf("cryptopuff: failed to unmarshal JSON: %v", err), http.StatusBadRequest)
		return
	}
	if err := b.UpdateHash(); err != nil {
		http.Error(w, fmt.Sprintf("cryptopuff: failed to update block hash: %v", err), http.StatusInternalServerError)
		return
	}

	err := s.db.AddBlock(&b)
	if err == ErrUnknownParent {
		peer := r.Header.Get(headerXPeer)
		go func() {
			if err := s.fetchBlocks(peer); err != nil {
				log.Printf("failed to fetch missing parent blocks from %v: %v\n", peer, err)
			}
		}()
		return
	} else if err != nil {
		http.Error(w, fmt.Sprintf("cryptopuff: failed to add block to database: %v", err), http.StatusInternalServerError)
		return
	}

	atomic.AddUint64(&s.bestBlockVersion, 1)
}

func (s *Server) addresses(w http.ResponseWriter, r *http.Request) {
	addrs, err := s.db.Addresses()
	if err != nil {
		http.Error(w, fmt.Sprintf("cryptopuff: failed to select addresses: %v", err), http.StatusInternalServerError)
		return
	}

	w.Header().Set(headerContentType, contentTypeJSON)
	if err := json.NewEncoder(w).Encode(addrs); err != nil {
		http.Error(w, fmt.Sprintf("cryptopuff: failed to marshal JSON: %v", err), http.StatusInternalServerError)
		return
	}
}

func (s *Server) setMinerAddress(w http.ResponseWriter, r *http.Request) {
	var addr Address
	if err := json.NewDecoder(r.Body).Decode(&addr); err != nil {
		http.Error(w, fmt.Sprintf("cryptopuff: failed to unmarshal JSON: %v", err), http.StatusBadRequest)
		return
	}

	if err := s.db.SetMinerAddress(addr); err != nil {
		http.Error(w, fmt.Sprintf("cryptopuff: failed to set miner address: %v", err), http.StatusInternalServerError)
		return
	}
}

func (s *Server) addKey(w http.ResponseWriter, r *http.Request) {
	v, err := strconv.Atoi(r.URL.Query().Get("version"))
	if err != nil {
		http.Error(w, fmt.Sprintf("cryptopuff: failed to convert version to int: %v", err), http.StatusBadRequest)
		return
	}

	b, err := ioutil.ReadAll(r.Body)
	if err != nil {
		http.Error(w, fmt.Sprintf("cryptopuff: failed to read body: %v", err), http.StatusBadRequest)
		return
	}

	k, err := DecodePrivateKeyPEM(b)
	if err != nil {
		http.Error(w, fmt.Sprintf("cryptopuff: failed to decode private key: %v", err), http.StatusBadRequest)
		return
	}

	a, err := s.db.AddKey(Version(v), k)
	if err != nil {
		http.Error(w, fmt.Sprintf("cryptopuff: failed to add key to the database: %v", err), http.StatusInternalServerError)
		return
	}

	w.Header().Set(headerContentType, contentTypeJSON)
	if err := json.NewEncoder(w).Encode(a); err != nil {
		http.Error(w, fmt.Sprintf("cryptopuff: failed to marshal JSON: %v", err), http.StatusInternalServerError)
		return
	}
}

func (s *Server) key(w http.ResponseWriter, r *http.Request) {
	addrStr, err := url.PathUnescape(chi.URLParam(r, "address"))
	if err != nil {
		http.Error(w, fmt.Sprintf("cryptopuff: failed to unescape address: %v", err), http.StatusBadRequest)
		return
	}

	addr, err := AddressFromString(addrStr)
	if err != nil {
		http.Error(w, fmt.Sprintf("cryptopuff: failed to decode address: %v", err), http.StatusBadRequest)
		return
	}

	key, err := s.db.Key(addr)
	if err != nil {
		http.Error(w, fmt.Sprintf("cryptopuff: failed to select key for address %v: %v", addr, err), http.StatusInternalServerError)
		return
	}

	w.Header().Set(headerContentType, contentTypePEM)
	if _, err := w.Write(EncodePrivateKeyPEM(key)); err != nil {
		http.Error(w, fmt.Sprintf("cryptopuff: failed to marshal JSON: %v", err), http.StatusInternalServerError)
		return
	}
}

func (s *Server) txs(w http.ResponseWriter, r *http.Request) {
	stxs, err := s.db.AllPendingTxs()
	if err != nil {
		http.Error(w, fmt.Sprintf("cryptopuff: failed to select pending transactions: %v", err), http.StatusInternalServerError)
		return
	}

	w.Header().Set(headerContentType, contentTypeJSON)
	if err := json.NewEncoder(w).Encode(stxs); err != nil {
		http.Error(w, fmt.Sprintf("cryptopuff: failed to marshal JSON: %v", err), http.StatusInternalServerError)
		return
	}
}

func (s *Server) addTx(w http.ResponseWriter, r *http.Request) {
	var stx SignedTx
	if err := json.NewDecoder(r.Body).Decode(&stx); err != nil {
		http.Error(w, fmt.Sprintf("cryptopuff: failed to unmarshal JSON: %v", err), http.StatusBadRequest)
		return
	}
	if err := stx.UpdateHash(); err != nil {
		http.Error(w, fmt.Sprintf("cryptopuff: failed to update transaction hash", err), http.StatusInternalServerError)
		return
	}

	if err := s.db.AddTx(&stx); err != nil {
		http.Error(w, fmt.Sprintf("cryptopuff: failed to add transaction to the database: %v", err), http.StatusInternalServerError)
		return
	}

	atomic.AddUint64(&s.bestBlockVersion, 1)
}

func (s *Server) fetchTxs(peer string) error {
	stxs, err := s.client.Txs(peer)
	if err != nil {
		return errors.Wrap(err, "cryptopuff: failed to download transactions")
	}

	for _, stx := range stxs {
		err := s.db.AddTx(&stx)
		if _, ok := err.(InvalidBlockError); ok {
			continue
		} else if err != nil {
			return errors.Wrap(err, "cryptopuff: failed to add transaction to the database")
		}
	}

	atomic.AddUint64(&s.bestBlockVersion, 1)
	return nil
}

func (s *Server) myTxs(w http.ResponseWriter, r *http.Request) {
	ptxs, err := s.db.MyTxs()
	if err != nil {
		http.Error(w, fmt.Sprintf("cryptopuff: failed to select my transactions: %v", err), http.StatusInternalServerError)
		return
	}

	w.Header().Set(headerContentType, contentTypeJSON)
	if err := json.NewEncoder(w).Encode(ptxs); err != nil {
		http.Error(w, fmt.Sprintf("cryptopuff: failed to marshal JSON: %v", err), http.StatusInternalServerError)
		return
	}
}

func (s *Server) signTx(w http.ResponseWriter, r *http.Request) {
	var tx Tx
	if err := json.NewDecoder(r.Body).Decode(&tx); err != nil {
		http.Error(w, fmt.Sprintf("cryptopuff: failed to unmarshal JSON: %v", err), http.StatusBadRequest)
		return
	}

	key, err := s.db.Key(tx.Source)
	if err != nil {
		http.Error(w, fmt.Sprintf("cryptopuff: failed to select private key for address %v: %v", tx.Source, err), http.StatusInternalServerError)
		return
	}

	stx, err := tx.Sign(key)
	if err != nil {
		http.Error(w, fmt.Sprintf("cryptopuff: failed to sign transaction: %v", err), http.StatusInternalServerError)
		return
	}

	w.Header().Set(headerContentType, contentTypeJSON)
	if err := json.NewEncoder(w).Encode(stx); err != nil {
		http.Error(w, fmt.Sprintf("cryptopuff: failed to marshal JSON: %v", err), http.StatusInternalServerError)
		return
	}
}

func (s *Server) broadcastTx(w http.ResponseWriter, r *http.Request) {
	var stx SignedTx
	if err := json.NewDecoder(r.Body).Decode(&stx); err != nil {
		http.Error(w, fmt.Sprintf("cryptopuff: failed to unmarshal JSON: %v", err), http.StatusBadRequest)
		return
	}
	if err := stx.UpdateHash(); err != nil {
		http.Error(w, fmt.Sprintf("cryptopuff: failed to update transaction hash: %v", err), http.StatusInternalServerError)
		return
	}

	if err := s.db.AddTx(&stx); err != nil {
		http.Error(w, fmt.Sprintf("cryptopuff: failed to add transaction to the database: %v", err), http.StatusInternalServerError)
		return
	}
	atomic.AddUint64(&s.bestBlockVersion, 1)

	peers, err := s.db.Peers()
	if err != nil {
		http.Error(w, fmt.Sprintf("cryptopuff: failed to select peers: %v", err), http.StatusInternalServerError)
		return
	}
	for _, peer := range peers {
		peer := peer
		go func() {
			if err := s.client.AddTx(peer, &stx); err != nil {
				log.Printf("cryptopuff: failed to notify peer %v about new transaction %v: %v\n", peer, stx.Hash, err)
			}
		}()
	}
}

func (s *Server) mine() {
	rand.Seed(time.Now().UnixNano())

newBestBlock:
	for {
		addr, err := s.db.MinerAddress()
		if err != nil {
			log.Fatalf("miner failed to get miner address: %v\n", err)
		}

		version := atomic.LoadUint64(&s.bestBlockVersion)
		block, err := s.db.BestBlock()
		if err != nil {
			log.Fatalf("miner failed to get best block: %v\n", err)
		}

		stxs, err := s.db.PendingTxs(block.Hash, 10)
		if err != nil {
			log.Fatalf("miner failed to get pending transactions: %v\n", err)
		}

		log.Printf("current tip: hash=%v, height=%v\n", block.Hash, block.Height)

		var next *Block
		for {
			if version != atomic.LoadUint64(&s.bestBlockVersion) {
				continue newBestBlock
			}

			var err error
			next, err = NewBlock(block, rand.Int63(), addr, s.blockReward, stxs)
			if err != nil {
				log.Fatalf("miner failed to create new block: %v\n", err)
			}
			if next.Hash.Valid() {
				break
			}

			//time.Sleep(5 * time.Microsecond)

			atomic.AddUint64(&s.hashesPerSec, 1)
		}

		if err := s.db.AddBlock(next); err != nil {
			log.Fatalf("miner failed to add block to the database: %v\n", err)
		}
		atomic.AddUint64(&s.bestBlockVersion, 1)

		peers, err := s.db.Peers()
		if err != nil {
			log.Fatalf("miner failed to select peers: %v\n", err)
		}
		for _, peer := range peers {
			peer := peer
			go func() {
				if err := s.client.AddBlock(peer, next); err != nil {
					log.Printf("failed to notify peer %v about new block %v: %v\n", peer, next.Hash, err)
				}
			}()
		}
	}
}

func (s *Server) periodicFullPeerSync() {
	t := time.NewTicker(time.Minute)
	for range t.C {
		peers, err := s.db.Peers()
		if err != nil {
			log.Fatalf("full peer sync scheduler failed to select peers: %v\n", err)
		}

		for _, peer := range peers {
			peer := peer
			go func() {
				_, wellKnown := s.wellKnownPeers[peer]
				if err := s.client.Ping(peer); err != nil && !wellKnown {
					if err := s.db.RemovePeer(peer); err != nil {
						log.Printf("failed to remove unresponsive peer %v from the database: %v\n", peer, err)
						return
					}
				}

				if err := s.fullPeerSync(peer); err != nil {
					log.Printf("full peer sync with existing peer failed: %v\n", err)
				}
			}()
		}
	}
}

func (s *Server) printHashesPerSec() {
	t := time.NewTicker(time.Second)
	for range t.C {
		h := atomic.SwapUint64(&s.hashesPerSec, 0)
		log.Printf("hashes per second: %v\n", h)
	}
}

func (s *Server) Serve() error {
	log.Printf("this machine has %v cores\n", runtime.NumCPU())

	go s.mine()
	go s.mine()
	go s.mine()
	go s.periodicFullPeerSync()
	go s.printHashesPerSec()

	for peer := range s.wellKnownPeers {
		if err := s.validateAndAddPeer(peer); err != nil {
			return errors.Wrap(err, "cryptopuff: failed to add well-known peer")
		}
	}

	if err := http.ListenAndServe(s.addr, s.router); err != nil {
		return errors.Wrap(err, "cryptopuff: ListenAndServe failed")
	}
	return nil
}
