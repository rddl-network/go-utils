package str_test

import (
	"testing"

	"github.com/rddl-network/go-utils/str"
	"github.com/stretchr/testify/assert"
)

func TestContainsString(t *testing.T) {
	var valid bool
	slice := []string{"foo", "bar", "baz"}

	// valid
	valid = str.ContainsString(slice, "foo")
	assert.True(t, valid)
	valid = str.ContainsString(slice, "bar")
	assert.True(t, valid)
	valid = str.ContainsString(slice, "baz")
	assert.True(t, valid)

	// invalid
	valid = str.ContainsString(slice, "boz")
	assert.False(t, valid)
}
