package signature

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"encoding/asn1"
	"encoding/hex"
	"errors"
	"math/big"

	"github.com/cosmos/cosmos-sdk/crypto/keys/secp256k1"
)

func ValidateSignature(hexMessage string, hexSignature string, hexPublicKey string) (bool, error) {
	messageBytes, signatureBytes, publicKeyBytes, err := decodeInputs(hexMessage, hexSignature, hexPublicKey)
	if err != nil {
		return false, err
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

// ValidateSECP256R1Signature takes the hex-encoded message together with r, s of the signature (combined as []byte{r.Bytes()..., s.Bytes()...})
// and x, y (combined as []byte{0x04, x.Bytes()..., y.Bytes()...}) of the public key
func ValidateSECP256R1Signature(hexMessage string, hexSignature string, hexPublicKey string) (bool, error) {
	_, signatureBytes, publicKeyBytes, err := decodeInputs(hexMessage, hexSignature, hexPublicKey)
	if err != nil {
		return false, err
	}

	pubKey, err := UncompressedBytesToPublicKey(publicKeyBytes)
	if err != nil {
		return false, err
	}

	rBytes, sBytes := signatureBytes[:len(signatureBytes)/2], signatureBytes[len(signatureBytes)/2:]
	r, s := new(big.Int).SetBytes(rBytes), new(big.Int).SetBytes(sBytes)

	hash := sha256.Sum256([]byte(hexMessage))
	isValid := ecdsa.Verify(pubKey, hash[:], r, s)
	if !isValid {
		return false, errors.New("invalid signature")
	}
	return isValid, nil
}

func UncompressedBytesToPublicKey(b []byte) (*ecdsa.PublicKey, error) {
	offset := 1
	if b[0] != 0x04 && len(b) == 64 {
		//return nil, errors.New("expected uncompressed point")
		offset = 0
	}

	curve := elliptic.P256()
	x := new(big.Int).SetBytes(b[offset : offset+curve.Params().BitSize/8])
	y := new(big.Int).SetBytes(b[offset+curve.Params().BitSize/8:])

	return &ecdsa.PublicKey{
		Curve: curve,
		X:     x,
		Y:     y,
	}, nil
}

func PublicKeyToUncompressedBytes(pub *ecdsa.PublicKey) []byte {
	xBytes := pub.X.Bytes()
	yBytes := pub.Y.Bytes()

	// Ensure the bytes are the correct length by adding padding if necessary
	curveBytes := (pub.Curve.Params().BitSize + 7) / 8 // Rounded up byte length
	if len(xBytes) < curveBytes {
		xBytes = append(make([]byte, curveBytes-len(xBytes)), xBytes...)
	}
	if len(yBytes) < curveBytes {
		yBytes = append(make([]byte, curveBytes-len(yBytes)), yBytes...)
	}

	return append([]byte{0x04}, append(xBytes, yBytes...)...) // 0x04 for uncompressed
}

func decodeInputs(hexMessage string, hexSignature string, hexPublicKey string) (msgBytes []byte, signBytes []byte, pubBytes []byte, err error) {
	// Convert the message, signature, and public key from hex to bytes
	msgBytes, err = hex.DecodeString(hexMessage)
	if err != nil {
		return nil, nil, nil, errors.New("invalid message hex string")
	}
	// Convert  signature, and public key from hex to bytes
	signBytes, err = hex.DecodeString(hexSignature)
	if err != nil {
		return nil, nil, nil, errors.New("invalid signature hex string")
	}
	pubBytes, err = hex.DecodeString(hexPublicKey)
	if err != nil {
		return nil, nil, nil, errors.New("invalid public key hex string")
	}
	return
}

func ValidateSECP256R1SignatureNew(hexMessage string, hexSignature string, hexPublicKey string) (bool, error) {
	_, sigBytes, publicKeyBytes, err := decodeInputs(hexMessage, hexSignature, hexPublicKey)
	if err != nil {
		return false, err
	}

	pubKey, err := UncompressedBytesToPublicKey(publicKeyBytes)
	if err != nil {
		return false, err
	}

	type ECDSASignature struct {
		R, S *big.Int
	}

	// Assuming asn1Data contains an ECDSA signature in DER format
	var signature ECDSASignature
	_, err = asn1.Unmarshal(sigBytes, &signature)
	if err != nil {
		return false, errors.New("unable to unmarshal signature")
	}

	hash := sha256.Sum256([]byte(hexMessage))
	isValid := ecdsa.Verify(pubKey, hash[:], signature.R, signature.S)
	if !isValid {
		return false, errors.New("invalid signature")
	}
	return isValid, nil
}
