package logger_test

import (
	"io"
	"os"
	"strings"
	"testing"

	"github.com/rddl-network/go-utils/logger"
	"github.com/stretchr/testify/assert"
)

func TestLogCaller(t *testing.T) {
	r, w, err := os.Pipe()
	assert.NoError(t, err)

	os.Stderr = w

	l := logger.GetLogger(logger.DEBUG)
	l.Error("msg", "this is an error")

	w.Close()

	stdErrOutput, err := io.ReadAll(r)
	assert.NoError(t, err)

	stdErrOutputStr := string(stdErrOutput)
	callerStr := strings.Split(stdErrOutputStr, " ")[1]
	assert.Equal(t, "caller=logger_test.go:20", callerStr)
}
