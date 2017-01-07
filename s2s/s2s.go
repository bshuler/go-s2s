package s2s

import (
	"bufio"
	"bytes"
	"fmt"
	"io"
	"math/rand"
	"net"
	"strings"
	"sync"
	"time"

	"encoding/binary"
)

type S2S struct {
	buf         *bufio.Writer
	conn        net.Conn
	initialized bool
	endpoint    string
	endpoints   []string
	closed      bool
	lastS       *config.Sample
	sent        int64
	bufferBytes int
}

type splunkSignature struct {
	signature  [128]byte
	serverName [256]byte
	mgmtPort   [16]byte
}

// Connect opens a connection to Splunk
// endpoint is the format of 'host:port'
// bufferBytes defines the size of the buffer before flushing
func (st *S2S) connect(endpoint string, bufferBytes int) error {
	var err error
	st.conn, err = net.DialTimeout("tcp", endpoint, 2*time.Second)
	st.bufferBytes = bufferBytes
	return err
}

// sendSig will write the signature to the connection if it has not already been written
// Create Signature element of the S2S Message.  Signature is C struct:
//
// struct S2S_Signature
// {
// 	char _signature[128];
// 	char _serverName[256];
// 	char _mgmtPort[16];
// };
func (st *S2S) sendSig() error {
	endpointParts := strings.Split(st.endpoint, ":")
	if len(endpointParts) != 2 {
		return fmt.Errorf("Endpoint malformed.  Should look like server:port")
	}
	serverName := endpointParts[0]
	mgmtPort := endpointParts[1]
	var sig splunkSignature
	copy(sig.signature[:], "--splunk-cooked-mode-v2--")
	copy(sig.serverName[:], serverName)
	copy(sig.mgmtPort[:], mgmtPort)
	buf := &bytes.Buffer{}
	binary.Write(buf, binary.BigEndian, sig.signature)
	binary.Write(buf, binary.BigEndian, sig.serverName)
	binary.Write(buf, binary.BigEndian, sig.mgmtPort)
	st.buf.Write(buf.Bytes())
	return nil
}

// encodeString encodes a string to be sent across the wire to Splunk
// Wire protocol has an unsigned integer of the length of the string followed
// by a null terminated string.
func encodeString(tosend string) []byte {
	// buf := bp.Get().(*bytes.Buffer)
	// defer bp.Put(buf)
	// buf.Reset()
	buf := &bytes.Buffer{}
	l := uint32(len(tosend) + 1)
	binary.Write(buf, binary.BigEndian, l)
	binary.Write(buf, binary.BigEndian, []byte(tosend))
	binary.Write(buf, binary.BigEndian, []byte{0})
	return buf.Bytes()
}

// encodeKeyValue encodes a key/value pair to send across the wire to splunk
// A key value pair is merely a concatenated set of encoded strings.
func encodeKeyValue(key, value string) []byte {
	// buf := bp.Get().(*bytes.Buffer)
	// defer bp.Put(buf)
	// buf.Reset()
	buf := &bytes.Buffer{}
	buf.Write(encodeString(key))
	buf.Write(encodeString(value))
	return buf.Bytes()
}

// EncodeEvent encodes a full Splunk event
func EncodeEvent(line map[string]string) []byte {
	// buf := bp.Get().(*bytes.Buffer)
	// defer bp.Put(buf)
	// buf.Reset()
	buf := &bytes.Buffer{}

	var msgSize uint32
	msgSize = 8 // Two unsigned 32 bit integers included, the number of maps and a 0 between the end of raw the _raw trailer
	maps := make([][]byte, 0)

	for k, v := range line {
		switch k {
		case "source":
			encodedSource := encodeKeyValue("MetaData:Source", "source::"+v)
			maps = append(maps, encodedSource)
			msgSize += uint32(len(encodedSource))
		case "sourcetype":
			encodedSourcetype := encodeKeyValue("MetaData:Sourcetype", "sourcetype::"+v)
			maps = append(maps, encodedSourcetype)
			msgSize += uint32(len(encodedSourcetype))
		case "host":
			encodedHost := encodeKeyValue("MetaData:Host", "host::"+v)
			maps = append(maps, encodedHost)
			msgSize += uint32(len(encodedHost))
		case "index":
			encodedIndex := encodeKeyValue("_MetaData:Index", v)
			maps = append(maps, encodedIndex)
			msgSize += uint32(len(encodedIndex))
		case "_raw":
			break
		default:
			encoded := encodeKeyValue(k, v)
			maps = append(maps, encoded)
			msgSize += uint32(len(encoded))
		}
	}

	encodedRaw := encodeKeyValue("_raw", line["_raw"])
	msgSize += uint32(len(encodedRaw))
	encodedRawTrailer := encodeString("_raw")
	msgSize += uint32(len(encodedRawTrailer))
	encodedDone := encodeKeyValue("_done", "_done")
	msgSize += uint32(len(encodedDone))

	binary.Write(buf, binary.BigEndian, msgSize)
	binary.Write(buf, binary.BigEndian, uint32(len(maps)+2)) // Include extra map for _done key and one for _raw
	for _, m := range maps {
		binary.Write(buf, binary.BigEndian, m)
	}
	binary.Write(buf, binary.BigEndian, encodedDone)
	binary.Write(buf, binary.BigEndian, encodedRaw)
	binary.Write(buf, binary.BigEndian, uint32(0))
	binary.Write(buf, binary.BigEndian, encodedRawTrailer)

	return buf.Bytes()
}

// Send sends an event to Splunk, represented as a map[string]string containing keys of index, host, source, sourcetype, and _raw
// It is a convenience function, wrapping EncodeEvent and Copy
func (st *S2S) Send(event map[string]string) error {
	return Copy(EncodeEvent(event))
}

// Copy takes a io.Reader and copies it to Splunk, needs to be encoded by EncodeEvent
func (st *S2S) Copy(r io.Reader) error {
	if st.initialized == false {
		err := st.newBuf(item)
		if err != nil {
			return err
		}
		err = st.sendSig()
		if err != nil {
			return err
		}
		st.initialized = true
	}
	bytes, err := io.Copy(st.buf, r)
	if err != nil {
		return err
	}

	st.sent += bytes
	if st.sent > int64(st.bufferBytes) {
		err := st.buf.Flush()
		if err != nil {
			return err
		}
		st.newBuf(item)
		st.sent = 0
	}
}

// Close disconnects from Splunk
func (st *S2S) Close() error {
	if !st.closed {
		err := st.buf.Flush()
		if err != nil {
			return err
		}
		err = st.conn.Close()
		if err != nil {
			return err
		}
		st.closed = true
	}
	return nil
}

func (st *S2S) newBuf(item *config.OutQueueItem) error {
	st.endpoint = st.endpoints[rand.Intn(len(st.endpoints))]
	err := st.Connect(st.endpoint)
	if err != nil {
		return err
	}
	st.buf = bufio.NewWriter(st.conn)
	return nil
}
