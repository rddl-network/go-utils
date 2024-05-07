package pki_test

import (
	"encoding/hex"
	"testing"

	"github.com/rddl-network/go-utils/pki"
	"github.com/stretchr/testify/assert"
)

func TestGetRandomPrivateKey(t *testing.T) {
	// valid
	pkSource, err := pki.GetRandomPrivateKey()
	assert.NoError(t, err)
	// should be 32 bytes (2 hex characters per byte) for secp256 curve
	assert.Equal(t, 64, len(pkSource))
}

func TestGenerateNewKeyPair(t *testing.T) {
	// valid
	pkSource := "b94fa8c5095409dbb313351d39328dbbee9414b43763c79c2177e81d5c2c0672"
	compressedPublicKey := "0371cfa1abe06a049f761d1f0529be834cc048fac8ea9a8ca9381ab09a0f4dc428"
	privateKey, publicKey, err := pki.GenerateNewKeyPair(pkSource)
	assert.NoError(t, err)
	assert.Equal(t, pkSource, hex.EncodeToString(privateKey.Serialize()))
	assert.Equal(t, compressedPublicKey, hex.EncodeToString(publicKey.SerializeCompressed()))

	// invalid
	pkSource = "helloworld"
	_, _, err = pki.GenerateNewKeyPair(pkSource)
	assert.Error(t, err)
}
