package agent

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestQueueIsBoundedAndDrainsInOrder(t *testing.T) {
	path := filepath.Join(t.TempDir(), "q.jsonl")
	q := Queue{Path: path, MaxBytes: 16}
	for _, item := range []string{"1111", "2222", "3333", "4444"} {
		if err := q.Enqueue([]byte(item)); err != nil {
			t.Fatal(err)
		}
	}
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if int64(len(b)) > q.MaxBytes {
		t.Fatalf("queue exceeded bound: %d > %d", len(b), q.MaxBytes)
	}
	var sent []string
	if err := q.Drain(func(p []byte) error { sent = append(sent, string(p)); return nil }); err != nil {
		t.Fatal(err)
	}
	want := []string{"2222", "3333", "4444"}
	if len(sent) != len(want) {
		t.Fatalf("unexpected drain order/content: %#v", sent)
	}
	for i := range want {
		if sent[i] != want[i] {
			t.Fatalf("unexpected drain order/content: got %#v want %#v", sent, want)
		}
	}
	if _, err := os.Stat(path); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("fully drained queue file must be removed, stat error=%v", err)
	}
}

func TestQueueDrainPreservesFailedAndRemainingPayloadsForRetry(t *testing.T) {
	path := filepath.Join(t.TempDir(), "q.jsonl")
	q := Queue{Path: path, MaxBytes: 64}
	for _, item := range []string{"one", "two", "three"} {
		if err := q.Enqueue([]byte(item)); err != nil {
			t.Fatal(err)
		}
	}

	var firstAttempt []string
	if err := q.Drain(func(p []byte) error {
		item := string(p)
		firstAttempt = append(firstAttempt, item)
		if item == "two" {
			return errors.New("temporary send failure")
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if len(firstAttempt) != 2 || firstAttempt[0] != "one" || firstAttempt[1] != "two" {
		t.Fatalf("unexpected first drain attempt: %#v", firstAttempt)
	}
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if got, want := string(b), "two\nthree\n"; got != want {
		t.Fatalf("failed and unattempted payloads must remain queued: got %q want %q", got, want)
	}

	var retry []string
	if err := q.Drain(func(p []byte) error {
		retry = append(retry, string(p))
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if len(retry) != 2 || retry[0] != "two" || retry[1] != "three" {
		t.Fatalf("unexpected retry drain: %#v", retry)
	}
	if _, err := os.Stat(path); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("recovered queue file must be removed, stat error=%v", err)
	}
}

func TestQueueStatsReportsBoundedPressure(t *testing.T) {
	path := filepath.Join(t.TempDir(), "q.jsonl")
	q := Queue{Path: path, MaxBytes: 20}

	empty, err := q.Stats()
	if err != nil {
		t.Fatal(err)
	}
	if empty.Bytes != 0 || empty.MaxBytes != 20 || empty.UsedPercent != 0 {
		t.Fatalf("unexpected empty queue stats: %#v", empty)
	}

	if err := q.Enqueue([]byte("123456789")); err != nil {
		t.Fatal(err)
	}
	stats, err := q.Stats()
	if err != nil {
		t.Fatal(err)
	}
	if stats.Bytes != 10 {
		t.Fatalf("expected payload plus newline to occupy 10 bytes, got %d", stats.Bytes)
	}
	if stats.MaxBytes != 20 || stats.UsedPercent != 50 {
		t.Fatalf("unexpected queue pressure stats: %#v", stats)
	}
}
