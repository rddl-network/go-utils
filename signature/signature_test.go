package signature_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"math/big"
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

func TestValidateSignaturePreset(t *testing.T) {
	pubkey := "03A772662A2FED007077DA4751455369C57168264A99932AA0190E02929A18863F"
	sig := "1F54A44CA6A60C8DDF721900DF96AEDCD8E13301DA8D03138679AEBA2C29501A10571731E405AF5BEE265E2BDD06CF9D44155246ED5521EA3BA5BDDA5ACB9850"

	valid, err := signature.ValidateSignature(pubkey, sig, pubkey)
	assert.True(t, valid)
	assert.NoError(t, err)
}

func TestValidateSECP256R1Signature(t *testing.T) {
	publicKeyString := "2f7cc9a2f286a2aa249bf441feb594872f43ead0a1f65a710aacad831b55eb3b8d816c7f2f6e9964222cbd3d9147999692527595b74064d62aed3d1b8a3b32be"
	curve := elliptic.P256()
	prvKey, err := ecdsa.GenerateKey(curve, rand.Reader)
	assert.NoError(t, err)

	pubKey := prvKey.PublicKey

	digest := []byte(publicKeyString)
	hash := sha256.Sum256(digest)
	r, s, err := ecdsa.Sign(rand.Reader, prvKey, hash[:])
	assert.NoError(t, err)

	var signBytes []byte
	signBytes = append(signBytes, r.Bytes()...)
	signBytes = append(signBytes, s.Bytes()...)

	//hexDigest := hex.EncodeToString(digest)
	hexSign := hex.EncodeToString(signBytes)
	hexPubKey := hex.EncodeToString(signature.PublicKeyToUncompressedBytes(&pubKey))

	isValid, err := signature.ValidateSECP256R1Signature(publicKeyString, hexSign, hexPubKey)
	assert.NoError(t, err)
	assert.True(t, isValid)

	// Verify with non hex encoded values
	isValid = ecdsa.Verify(&pubKey, hash[:], r, s)
	assert.True(t, isValid)
}

func TestPublicKeyImport(t *testing.T) {
	publicKeyString := "2f7cc9a2f286a2aa249bf441feb594872f43ead0a1f65a710aacad831b55eb3b8d816c7f2f6e9964222cbd3d9147999692527595b74064d62aed3d1b8a3b32be"

	// Decode the hex-encoded string into bytes
	publicKeyBytes, err := hex.DecodeString(publicKeyString)
	if err != nil {
		fmt.Println("Error decoding public key string:", err)
		return
	}

	// Extract X and Y coordinates from the byte slice
	x := new(big.Int).SetBytes(publicKeyBytes[0:32]) // Skip the prefix byte (0x04)
	y := new(big.Int).SetBytes(publicKeyBytes[32:])

	// Create the ECDSA public key
	publicKey := ecdsa.PublicKey{
		Curve: elliptic.P256(),
		X:     x,
		Y:     y,
	}
	print(publicKey.X)
}

func TestHashingOfPubKey(t *testing.T) {
	ref_pubkey := "c59ee9fda66013cd2b427aff34a9203a934e6841aa87e242dc995313c72e42922d3dfb5f9fdf5871500c101335271e40035805703749c4f6da3b3e688480cc58"
	ref_hash := "b33a84c7de03986194d34dd8bd3b9ec7d4dd73aafb1010386c23e2625072e2b3"
	refHashBytes, err := hex.DecodeString(ref_hash)
	assert.NoError(t, err)
	digest := []byte(ref_pubkey)
	hash := sha256.Sum256(digest)
	assert.Equal(t, [32]uint8(refHashBytes), hash)
}

func TestValidateSECP256R1SignaturePreset(t *testing.T) {
	ref_pubkey := "80a0b8808ec5b932c917201a26afc16899e400d86804a3171665e539c2384d0f8d0eb2dc74c2ba4ca52c53b2b6e331cac95c4432054a320314225dd6b03433fa"
	ref_signature_asn1 := "30450221009b71d5cab046339436430a18de039fe14eca053a7c13bc7de302be767ea3b836022041aa5097ed5732832d04b47a58687cb81a6b218a9e984886dbbfee283889a9f3"

	isValid, err := signature.ValidateSECP256R1SignatureNew(ref_pubkey, ref_signature_asn1, ref_pubkey)
	assert.NoError(t, err)
	assert.Equal(t, true, isValid)
}
