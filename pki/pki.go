package pki

import (
	"encoding/hex"
	"fmt"

	btcec "github.com/btcsuite/btcd/btcec/v2"
	"github.com/decred/dcrd/dcrec/secp256k1/v4"
	hexutil "github.com/rddl-network/go-utils/hex"
)

func GetRandomPrivateKey(n int) (string, error) {
	return hexutil.RandomHex(n)
}

func GenerateNewKeyPair(pkSource string) (privateKey *secp256k1.PrivateKey, publicKey *secp256k1.PublicKey, err error) {
	privateKeyBytes, err := hex.DecodeString(pkSource)
	if err != nil {
		err = fmt.Errorf("failed to decode private key: %w", err)
		return
	}
	// Initialize a secp256k1 private key object.
	privateKey, publicKey = btcec.PrivKeyFromBytes(privateKeyBytes)
	return
}
