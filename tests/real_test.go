package tests

import (
	"io/ioutil"
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

func TestS2SNoTLS(t *testing.T) {
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
		_, err = s.Send(event)
		assert.NoError(t, err)
	}
}

func TestS2STLSNoCert(t *testing.T) {
	if runTest {
		s, err := s2s.NewS2STLS([]string{"localhost:9998"}, 0, true, "", "", true)
		assert.NoError(t, err)
		event := map[string]string{
			"index":      "main",
			"host":       "test",
			"source":     "s2s-test-tlsnocert",
			"sourcetype": "s2s-testst-tlsnocert",
			"_raw":       "testing!!",
		}
		_, err = s.Send(event)
		assert.NoError(t, err)
	}
}

func TestS2STLSCert(t *testing.T) {
	if runTest {
		cert, err := ioutil.ReadFile("c:\\splunk\\etc\\auth\\cacert.pem")
		assert.NoError(t, err)
		s, err := s2s.NewS2STLS([]string{"localhost:9998"}, 0, true, string(cert), "", false)
		assert.NoError(t, err)
		event := map[string]string{
			"index":      "main",
			"host":       "test",
			"source":     "s2s-test-tlscert",
			"sourcetype": "s2s-testst-tlscert",
			"_raw":       "testing!!!",
		}
		_, err = s.Send(event)
		assert.NoError(t, err)
	}
}
