package protocol

import (
	"errors"
	"testing"
	"time"
)

func TestSignVerify(t *testing.T) {
	secret := []byte("unit-test-secret")
	body := []byte(`{"ok":true}`)
	now := time.Unix(1_700_000_000, 0)
	sig := Sign(secret, now.Unix(), "nonce-1", body)
	if err := Verify(secret, "1700000000", "nonce-1", sig, body, now, 2*time.Minute); err != nil {
		t.Fatalf("verify failed: %v", err)
	}
	if err := Verify(secret, "1700000000", "nonce-1", sig, []byte(`{"ok":false}`), now, 2*time.Minute); !errors.Is(err, ErrBadSignature) {
		t.Fatalf("expected bad signature, got %v", err)
	}
}

func TestVerifyRejectsStaleTimestamp(t *testing.T) {
	secret := []byte("unit-test-secret")
	body := []byte("x")
	sig := Sign(secret, 100, "n", body)
	err := Verify(secret, "100", "n", sig, body, time.Unix(1000, 0), 2*time.Minute)
	if !errors.Is(err, ErrStaleRequest) {
		t.Fatalf("expected stale request, got %v", err)
	}
}

func TestVerifyRejectsMalformedFutureAndTamperedNonce(t *testing.T) {
	secret := []byte("unit-test-secret")
	body := []byte("x")
	now := time.Unix(1_700_000_000, 0)
	validTimestamp := now.Unix()
	validNonce := "nonce-a"
	validSignature := Sign(secret, validTimestamp, validNonce, body)

	tests := []struct {
		name      string
		timestamp string
		nonce     string
		signature string
		want      error
	}{
		{name: "missing timestamp", timestamp: "", nonce: validNonce, signature: validSignature, want: ErrBadTimestamp},
		{name: "malformed timestamp", timestamp: "not-a-timestamp", nonce: validNonce, signature: validSignature, want: ErrBadTimestamp},
		{name: "overflow timestamp", timestamp: "9223372036854775808", nonce: validNonce, signature: validSignature, want: ErrBadTimestamp},
		{name: "future timestamp", timestamp: "1700000121", nonce: validNonce, signature: Sign(secret, validTimestamp+121, validNonce, body), want: ErrStaleRequest},
		{name: "tampered nonce", timestamp: "1700000000", nonce: "nonce-b", signature: validSignature, want: ErrBadSignature},
		{name: "malformed signature", timestamp: "1700000000", nonce: validNonce, signature: "not-hex", want: ErrBadSignature},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := Verify(secret, tc.timestamp, tc.nonce, tc.signature, body, now, 2*time.Minute)
			if !errors.Is(err, tc.want) {
				t.Fatalf("expected %v, got %v", tc.want, err)
			}
		})
	}
}
