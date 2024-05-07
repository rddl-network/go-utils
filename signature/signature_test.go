package signature_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"testing"

	"github.com/cosmos/cosmos-sdk/crypto/keys/secp256k1"
	"github.com/rddl-network/go-utils/signature"
	"github.com/stretchr/testify/assert"
)

func TestValidateSignature(t *testing.T) {
	privKey := secp256k1.GenPrivKey()
	pubKey := privKey.PubKey()

	msg := []byte("msg")
	sign, err := privKey.Sign(msg)
	assert.NoError(t, err)

	hexMsg := hex.EncodeToString(msg)
	hexSign := hex.EncodeToString(sign)
	hexPublicKey := hex.EncodeToString(pubKey.Bytes())

	valid, err := signature.ValidateSignature(hexMsg, hexSign, hexPublicKey)
	assert.True(t, valid)
	assert.NoError(t, err)
}

func TestValidateSECP256R1Signature(t *testing.T) {
	curve := elliptic.P256()
	prvKey, err := ecdsa.GenerateKey(curve, rand.Reader)
	assert.NoError(t, err)

	pubKey := prvKey.PublicKey

	digest := []byte("msg")
	hash := sha256.Sum256(digest)
	r, s, err := ecdsa.Sign(rand.Reader, prvKey, hash[:])
	assert.NoError(t, err)

	var signBytes []byte
	signBytes = append(signBytes, r.Bytes()...)
	signBytes = append(signBytes, s.Bytes()...)

	hexDigest := hex.EncodeToString(digest)
	hexSign := hex.EncodeToString(signBytes)
	hexPubKey := hex.EncodeToString(signature.PublicKeyToUncompressedBytes(&pubKey))

	isValid, err := signature.ValidateSECP256R1Signature(hexDigest, hexSign, hexPubKey)
	assert.NoError(t, err)
	assert.True(t, isValid)

	// Verify with non hex encoded values
	isValid = ecdsa.Verify(&pubKey, hash[:], r, s)
	assert.True(t, isValid)
}
