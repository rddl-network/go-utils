# signature
The signature package serves a centralized module for validating signatures.

## Example Usage
```go
package main

import (
    "log"

    "github.com/rddl-network/go-utils/signature"
    "github.com/cosmos/cosmos-sdk/crypto/keys/secp256k1"
)

func main() {
    privKey := secp256k1.GenPrivKey()
	pubKey := privKey.PubKey()
    
    msg := "msg"
    sign, err := privKey.Sign([]byte(msg))
    if err != nil {
        log.Fatalln(err)
    }

    hexMsg := hex.EncodeToString([]byte(msg))
	hexSign := hex.EncodeToString(sign)
	hexPublicKey := hex.EncodeToString(pubKey.Bytes())
    
    isValid, err := signature.ValidateSignature(hexMsg, hexSign, hexPublicKey)
    if err != nil {
        log.Fatalln(err)
    }
}
```
