package proto

import (
	"bytes"
	"crypto/rand"
	"testing"
)

func TestFilePayloadEncodingAndBoundedDecoding(t *testing.T) {
	data := bytes.Repeat([]byte("a compressed file\n"), 10000)
	meta, wire, err := EncodeFilePayload(data)
	if err != nil || meta.Encoding != FileEncodingGzip || meta.WireSize >= meta.Size {
		t.Fatalf("expected smaller gzip payload: %+v, %v", meta, err)
	}
	got, err := DecodeFilePayload(meta, wire)
	if err != nil || !bytes.Equal(got, data) {
		t.Fatalf("gzip round trip failed: %v", err)
	}

	understated := meta
	understated.Size = meta.WireSize + 1
	if _, err := DecodeFilePayload(understated, wire); err == nil {
		t.Fatal("gzip decoded beyond the declared size")
	}
	oversized := meta
	oversized.Size = MaxFileTransferBytes + 1
	if _, err := DecodeFilePayload(oversized, wire); err == nil {
		t.Fatal("accepted an oversized file")
	}
	withTrailingData := meta
	withTrailingData.WireSize++
	if _, err := DecodeFilePayload(withTrailingData, append(bytes.Clone(wire), 0)); err == nil {
		t.Fatal("accepted trailing gzip data")
	}
	corrupt := bytes.Clone(wire)
	corrupt[len(corrupt)-8] ^= 0xff
	if _, err := DecodeFilePayload(meta, corrupt); err == nil {
		t.Fatal("accepted a gzip checksum mismatch")
	}

	noise := make([]byte, 8192)
	if _, err := rand.Read(noise); err != nil {
		t.Fatal(err)
	}
	meta, wire, err = EncodeFilePayload(noise)
	if err != nil || meta.Encoding != FileEncodingIdentity || !bytes.Equal(wire, noise) {
		t.Fatalf("expected incompressible payload unchanged: %+v, %v", meta, err)
	}
}
