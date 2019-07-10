package log

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func init() {
	InitLogger("", "debug")
}

func TestGetCallerInfo(t *testing.T) {
	logPrefix := getCallerInfo()
	assert.Equal(t, logPrefix, "[testing/testing.go] [tRunner]", "Log prefix not equal to expected")
}
