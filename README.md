# Go-S2S
[![](https://godoc.org/github.com/coccyx/go-s2s/s2s?status.svg)](http://godoc.org/github.com/coccyx/go-s2s/s2s)

Go S2S is a client implementation of the Splunk to Splunk protocol in Golang.  It allows you to send structured data to Splunk using the same protocol as a Splunk forwarder.

Sample Usage:

        s, err := s2s.NewS2S([]string{"localhost:9997"}, 0)
		event := map[string]string{
			"index":      "main",
			"host":       "host",
			"source":     "myprog",
			"sourcetype": "myprog",
			"_raw":       "Here's an event!",
		}
		err = s.Send(event)