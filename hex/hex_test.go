package hex_test

import (
	"testing"

	"github.com/rddl-network/go-utils/hex"
	"github.com/stretchr/testify/assert"
)

func TestIsValidHex(t *testing.T) {
	// valid
	hexString := "0123456789abcdef"
	valid := hex.IsValidHex(hexString)
	assert.True(t, valid)

	// invalid
	hexString = "helloworld"
	valid = hex.IsValidHex(hexString)
	assert.False(t, valid)
}

func TestRandomHex(t *testing.T) {
	hexString, err := hex.RandomHex(16)
	valid := hex.IsValidHex(hexString)
	assert.True(t, valid)
	assert.NoError(t, err)
}
