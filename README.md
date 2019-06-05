# Netcraft-Cryptopuff
Winners of the Cryptopuff challenge by Netcraft

# Cryptocurrencies for fun and profit

## Exploits

- find 2 public keys that map to the same address
- use external machine for more computation
- brute force into others’ machine
- brute force cryptopuffd RPC interface
- brute force MySQL database if port is public

bad code:
- SHA256 vs MD5
- RSA keys shorter than 2048 bits (if <256 bits, easy to find private key)
- hash collisions
- integer overflow
- weak seed for random number generation

## Defense

- delete private key from server
