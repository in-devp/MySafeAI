package browserbridge

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"io"
	"testing"
)

func frame(body string) []byte {
	data := make([]byte, 4, len(body)+4)
	binary.LittleEndian.PutUint32(data, uint32(len(body)))
	return append(data, body...)
}

type byteReader struct{ io.Reader }

func (r byteReader) Read(data []byte) (int, error) { return r.Reader.Read(data[:1]) }

type byteWriter struct{ bytes.Buffer }

func (w *byteWriter) Write(data []byte) (int, error) { return w.Buffer.Write(data[:1]) }

func TestNativeFramingHandlesFragmentedPipeAndRefreshesEveryRequest(t *testing.T) {
	input := append(frame(`{"op":"status"}`), frame(`{"op":"status"}`)...)
	var output byteWriter
	calls := 0
	err := Serve(byteReader{bytes.NewReader(input)}, &output, func() Response {
		calls++
		if calls == 1 {
			return Response{Protocol: 1, Allowed: true, State: "trusted"}
		}
		return Unavailable()
	})
	if err != nil {
		t.Fatal(err)
	}
	if calls != 2 {
		t.Fatalf("status reads %d", calls)
	}
	for index := range 2 {
		var length uint32
		if err := binary.Read(&output.Buffer, binary.LittleEndian, &length); err != nil {
			t.Fatal(err)
		}
		data := make([]byte, length)
		if _, err := io.ReadFull(&output.Buffer, data); err != nil {
			t.Fatal(err)
		}
		var r Response
		if err := json.Unmarshal(data, &r); err != nil {
			t.Fatal(err)
		}
		if r.Allowed != (index == 0) {
			t.Fatalf("response %d: %+v", index, r)
		}
	}
	if output.Len() != 0 {
		t.Fatal("non-protocol stdout")
	}
}

func TestNativeRejectsMalformedMessagesWithoutStatusRead(t *testing.T) {
	oversized := make([]byte, 4)
	binary.LittleEndian.PutUint32(oversized, MaxFrameSize+1)
	for _, input := range [][]byte{
		{1}, {1, 0, 0}, {0, 0, 0, 0}, oversized, {10, 0, 0, 0, '{'},
		frame(`{"op":"disable"}`), frame(`{"op":"status","url":"https://example.com"}`),
		frame(`{"op":"status"}{}`), frame("null"), frame("[]"), frame(string([]byte{0xff})),
	} {
		var output bytes.Buffer
		calls := 0
		err := Serve(bytes.NewReader(input), &output, func() Response { calls++; return Unavailable() })
		if err == nil || calls != 0 || output.Len() != 0 {
			t.Fatalf("accepted malformed frame %q: calls %d, error %v", input, calls, err)
		}
	}
}

func TestNativeCleanEOF(t *testing.T) {
	if err := Serve(bytes.NewReader(nil), io.Discard, Unavailable); err != nil {
		t.Fatal(err)
	}
}
