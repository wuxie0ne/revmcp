package proto

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"errors"
	"testing"
)

func TestFrameRoundTrip(t *testing.T) {
	t.Parallel()

	want := Request{
		ID:      "req-1",
		TraceID: "trace-abc",
		Method:  MethodSysInfo,
		Params:  json.RawMessage(`{"detail":true}`),
	}

	var buf bytes.Buffer
	if err := WriteFrame(&buf, want); err != nil {
		t.Fatalf("WriteFrame failed: %v", err)
	}

	var got Request
	if err := ReadFrame(&buf, &got); err != nil {
		t.Fatalf("ReadFrame failed: %v", err)
	}

	if got.ID != want.ID || got.TraceID != want.TraceID || got.Method != want.Method {
		t.Fatalf("round-trip mismatch: got %+v, want %+v", got, want)
	}
	if string(got.Params) != string(want.Params) {
		t.Fatalf("params mismatch: got %s, want %s", got.Params, want.Params)
	}
}

func TestReadFrameRejectsOversizedHeader(t *testing.T) {
	t.Parallel()

	var buf bytes.Buffer
	var hdr [4]byte
	binary.BigEndian.PutUint32(hdr[:], MaxFrameSize+1)
	buf.Write(hdr[:])

	var req Request
	err := ReadFrame(&buf, &req)
	if !errors.Is(err, ErrFrameTooLarge) {
		t.Fatalf("expected ErrFrameTooLarge, got: %v", err)
	}
}

func TestReadFrameRejectsEmptyFrame(t *testing.T) {
	t.Parallel()

	var buf bytes.Buffer
	buf.Write([]byte{0, 0, 0, 0})

	var req Request
	err := ReadFrame(&buf, &req)
	if !errors.Is(err, ErrEmptyFrame) {
		t.Fatalf("expected ErrEmptyFrame, got: %v", err)
	}
}

func TestWriteFrameRejectsOversizedPayload(t *testing.T) {
	t.Parallel()

	big := make([]byte, MaxFrameSize+10)
	for i := range big {
		big[i] = 'a'
	}

	var buf bytes.Buffer
	err := WriteFrame(&buf, map[string]string{"data": string(big)})
	if !errors.Is(err, ErrFrameTooLarge) {
		t.Fatalf("expected ErrFrameTooLarge, got: %v", err)
	}
}

func TestParseModeAndAllows(t *testing.T) {
	t.Parallel()

	if _, err := ParseMode("invalid"); err == nil {
		t.Fatal("expected error for unrecognized mode")
	}
	if _, err := ParseMode(""); err == nil {
		t.Fatal("expected error for empty mode")
	}

	ro, err := ParseMode("readonly")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !ro.Allows(ModeReadOnly) || ro.Allows(ModeRestricted) || ro.Allows(ModeFull) {
		t.Fatalf("readonly privilege checks failed")
	}
	if !ModeRestricted.Allows(ModeReadOnly) || !ModeRestricted.Allows(ModeRestricted) || ModeRestricted.Allows(ModeFull) {
		t.Fatalf("restricted privilege checks failed")
	}
	if !ModeFull.Allows(ModeFull) || !ModeFull.Allows(ModeRestricted) || !ModeFull.Allows(ModeReadOnly) {
		t.Fatalf("full privilege checks failed")
	}
	if Mode("unknown").Allows(ModeReadOnly) {
		t.Fatal("unknown mode must fail closed")
	}
}
