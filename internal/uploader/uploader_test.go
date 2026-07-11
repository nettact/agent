package uploader

import (
	"context"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"

	"github.com/nettact/protocol/telemetry"
	"github.com/nettact/protocol/wire"
)

// jsonOnlyServer simulates a pre-protobuf server: it 400s any protobuf upload
// and accepts JSON, replying with a JSON ack. It records how many protobuf and
// JSON requests it saw.
func jsonOnlyServer(t *testing.T) (*httptest.Server, *int32, *int32) {
	t.Helper()
	var protoHits, jsonHits int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if wire.Negotiate(r.Header.Get("Content-Type")) == wire.ContentTypeProtobuf {
			atomic.AddInt32(&protoHits, 1)
			http.Error(w, "invalid packet: unsupported", http.StatusBadRequest)
			return
		}
		atomic.AddInt32(&jsonHits, 1)
		data, _ := wire.MarshalAck(wire.Ack{HighestSequence: 7}, wire.ContentTypeJSON)
		w.Header().Set("Content-Type", wire.ContentTypeJSON)
		_, _ = w.Write(data)
	}))
	t.Cleanup(srv.Close)
	return srv, &protoHits, &jsonHits
}

// TestUploadFallsBackToJSON verifies that a protobuf-default uploader hitting a
// JSON-only server downgrades and retries in JSON (so the WAL keeps draining),
// and that the downgrade is sticky for subsequent uploads.
func TestUploadFallsBackToJSON(t *testing.T) {
	srv, protoHits, jsonHits := jsonOnlyServer(t)
	up := New(Options{ServerURL: srv.URL, Token: "t", Format: wire.ContentTypeProtobuf})

	ack, err := up.Upload(context.Background(), telemetry.Packet{Sequence: 1})
	if err != nil {
		t.Fatalf("first upload should succeed via JSON fallback: %v", err)
	}
	if ack.HighestSequence != 7 {
		t.Errorf("ack highest_sequence = %d, want 7", ack.HighestSequence)
	}
	if got := atomic.LoadInt32(protoHits); got != 1 {
		t.Errorf("expected exactly 1 protobuf attempt, got %d", got)
	}
	if got := atomic.LoadInt32(jsonHits); got != 1 {
		t.Errorf("expected exactly 1 JSON retry, got %d", got)
	}
	if f := up.currentFormat(); f != wire.ContentTypeJSON {
		t.Errorf("format should have downgraded to JSON, got %q", f)
	}

	// Second upload must go straight to JSON (no repeated protobuf attempt).
	if _, err := up.Upload(context.Background(), telemetry.Packet{Sequence: 2}); err != nil {
		t.Fatalf("second upload: %v", err)
	}
	if got := atomic.LoadInt32(protoHits); got != 1 {
		t.Errorf("sticky downgrade broken: protobuf attempts = %d, want 1", got)
	}
	if got := atomic.LoadInt32(jsonHits); got != 2 {
		t.Errorf("expected 2 JSON uploads total, got %d", got)
	}
}

// TestUploadProtobufWhenAccepted confirms no needless downgrade when the server
// accepts protobuf: exactly one attempt, format stays protobuf.
func TestUploadProtobufWhenAccepted(t *testing.T) {
	var hits int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&hits, 1)
		ct := wire.Negotiate(r.Header.Get("Accept"))
		data, _ := wire.MarshalAck(wire.Ack{HighestSequence: 3}, ct)
		w.Header().Set("Content-Type", ct)
		_, _ = w.Write(data)
	}))
	t.Cleanup(srv.Close)

	up := New(Options{ServerURL: srv.URL, Token: "t", Format: wire.ContentTypeProtobuf})
	ack, err := up.Upload(context.Background(), telemetry.Packet{Sequence: 1})
	if err != nil {
		t.Fatalf("upload: %v", err)
	}
	if ack.HighestSequence != 3 {
		t.Errorf("ack = %d, want 3", ack.HighestSequence)
	}
	if got := atomic.LoadInt32(&hits); got != 1 {
		t.Errorf("expected 1 attempt, got %d", got)
	}
	if f := up.currentFormat(); f != wire.ContentTypeProtobuf {
		t.Errorf("format should stay protobuf, got %q", f)
	}
}
