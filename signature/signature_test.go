package signature_test

import (
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
