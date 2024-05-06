package signature

import (
	"encoding/hex"
	"errors"

	"github.com/cosmos/cosmos-sdk/crypto/keys/secp256k1"
)

func ValidateSignature(hexMessage string, hexSignature string, hexPublicKey string) (bool, error) {
	// Convert the message, signature, and public key from hex to bytes
	messageBytes, err := hex.DecodeString(hexMessage)
	if err != nil {
		return false, errors.New("invalid message hex string")
	}
	// Convert  signature, and public key from hex to bytes
	signatureBytes, err := hex.DecodeString(hexSignature)
	if err != nil {
		return false, errors.New("invalid signature hex string")
	}
	publicKeyBytes, err := hex.DecodeString(hexPublicKey)
	if err != nil {
		return false, errors.New("invalid public key hex string")
	}

	// Create a secp256k1 public key object
	pubKey := &secp256k1.PubKey{Key: publicKeyBytes}

	// Verify the signature
	isValid := pubKey.VerifySignature(messageBytes, signatureBytes)
	if !isValid {
		return false, errors.New("invalid signature")
	}
	return isValid, nil
}
