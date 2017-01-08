package tests

import (
	"testing"

	"github.com/coccyx/go-s2s/s2s"
	"github.com/stretchr/testify/assert"
)

var (
	runTest bool
)

func init() {
	runTest = true
}

func TestS2S(t *testing.T) {
	if runTest {
		s, err := s2s.NewS2S([]string{"localhost:9997"}, 0)
		assert.NoError(t, err)
		event := map[string]string{
			"index":      "main",
			"host":       "test",
			"source":     "s2s-test",
			"sourcetype": "s2s-testst",
			"_raw":       "testing",
		}
		s.Send(event)
	}
}
