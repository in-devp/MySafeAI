package browserbridge

import (
	"encoding/binary"
	"encoding/json"
	"errors"
	"io"
	"unicode/utf8"
)

const MaxFrameSize = 64 * 1024

// Serve uses binary stdin/stdout only; all current release architectures are
// little-endian. Unknown or malformed requests close the pipe, denying access.
func Serve(input io.Reader, output io.Writer, status func() Response) error {
	for {
		var header [4]byte
		_, err := io.ReadFull(input, header[:])
		if errors.Is(err, io.EOF) {
			return nil
		}
		if err != nil {
			return errors.New("incomplete native message header")
		}
		size := binary.LittleEndian.Uint32(header[:])
		if size == 0 || size > MaxFrameSize {
			return errors.New("invalid native message size")
		}
		data := make([]byte, size)
		if _, err := io.ReadFull(input, data); err != nil {
			return errors.New("incomplete native message")
		}
		var request struct {
			Op string `json:"op"`
		}
		if !utf8.Valid(data) || strictJSON(data, &request) != nil || request.Op != "status" {
			return errors.New("invalid native message")
		}
		response, err := json.Marshal(status())
		if err != nil || len(response) > MaxFrameSize {
			return errors.New("invalid native response")
		}
		binary.LittleEndian.PutUint32(header[:], uint32(len(response)))
		if err := writeAll(output, header[:]); err != nil {
			return err
		}
		if err := writeAll(output, response); err != nil {
			return err
		}
	}
}

func writeAll(output io.Writer, data []byte) error {
	for len(data) > 0 {
		n, err := output.Write(data)
		if err != nil {
			return err
		}
		if n <= 0 || n > len(data) {
			return io.ErrShortWrite
		}
		data = data[n:]
	}
	return nil
}
