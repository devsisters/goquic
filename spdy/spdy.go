package spdy

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"net/http"
)

/* SPDY Frame Parsing (from github.com/SlyMarbo/spdy ) */

// ReadExactly is used to ensure that the given number of bytes
// are read if possible, even if multiple calls to Read
// are required.
func ReadExactly(r io.Reader, i int) ([]byte, error) {
	out := make([]byte, i)
	in := out[:]
	for i > 0 {
		if r == nil {
			return nil, errors.New("Error: Connection is nil.")
		}
		if n, err := r.Read(in); err != nil {
			return nil, err
		} else {
			in = in[n:]
			i -= n
		}
	}
	return out, nil
}

func BytesToUint32(b []byte) uint32 {
	return (uint32(b[0]) << 24) + (uint32(b[1]) << 16) + (uint32(b[2]) << 8) + uint32(b[3])
}

func ParseHeaders(reader io.Reader) (http.Header, error) {
	// Maximum frame size (2 ** 24 -1).
	const MAX_FRAME_SIZE = 0xffffff

	// SPDY/3 uses 32-bit fields.
	size := 4
	bytesToInt := func(b []byte) int {
		return int(BytesToUint32(b))
	}

	// Read in the number of name/value pairs.
	pairs, err := ReadExactly(reader, size)
	if err != nil {
		return nil, err
	}
	numNameValuePairs := bytesToInt(pairs)

	header := make(http.Header)
	bounds := MAX_FRAME_SIZE - 12 // Maximum frame size minus maximum non-header data (SYN_STREAM)
	for i := 0; i < numNameValuePairs; i++ {
		var nameLength, valueLength int

		// Get the name's length.
		length, err := ReadExactly(reader, size)
		if err != nil {
			return nil, err
		}
		nameLength = bytesToInt(length)
		bounds -= size

		if nameLength > bounds {
			fmt.Printf("Error: Maximum header length is %d. Received name length %d.\n", bounds, nameLength)
			return nil, errors.New("Error: Incorrect header name length.")
		}
		bounds -= nameLength

		// Get the name.
		name, err := ReadExactly(reader, nameLength)
		if err != nil {
			return nil, err
		}

		// Get the value's length.
		length, err = ReadExactly(reader, size)
		if err != nil {
			return nil, err
		}
		valueLength = bytesToInt(length)
		bounds -= size

		if valueLength > bounds {
			fmt.Printf("Error: Maximum header length is %d. Received values length %d.\n", bounds, valueLength)
			return nil, errors.New("Error: Incorrect header values length.")
		}
		bounds -= valueLength

		// Get the values.
		values, err := ReadExactly(reader, valueLength)
		if err != nil {
			return nil, err
		}

		// Split the value on null boundaries.
		for _, value := range bytes.Split(values, []byte{'\x00'}) {
			header.Add(string(name), string(value))
		}
	}

	return header, nil
}
