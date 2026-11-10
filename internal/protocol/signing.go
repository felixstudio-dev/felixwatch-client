package protocol

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"strconv"
	"time"
)

var (
	ErrBadSignature = errors.New("invalid signature")
	ErrStaleRequest = errors.New("request timestamp outside allowed skew")
	ErrBadTimestamp = errors.New("invalid timestamp")
)

func canonical(timestamp int64, nonce string, body []byte) []byte {
	prefix := strconv.FormatInt(timestamp, 10) + "\n" + nonce + "\n"
	msg := make([]byte, 0, len(prefix)+len(body))
	msg = append(msg, prefix...)
	msg = append(msg, body...)
	return msg
}
func Sign(secret []byte, timestamp int64, nonce string, body []byte) string {
	mac := hmac.New(sha256.New, secret)
	_, _ = mac.Write(canonical(timestamp, nonce, body))
	return hex.EncodeToString(mac.Sum(nil))
}

func Verify(secret []byte, timestampText, nonce, signature string, body []byte, now time.Time, maxSkew time.Duration) error {
	ts, err := strconv.ParseInt(timestampText, 10, 64)
	if err != nil {
		return ErrBadTimestamp
	}
	requestTime := time.Unix(ts, 0)
	delta := now.Sub(requestTime)
	if delta < 0 {
		delta = -delta
	}
	if delta > maxSkew {
		return ErrStaleRequest
	}
	expected := Sign(secret, ts, nonce, body)
	provided, err := hex.DecodeString(signature)
	if err != nil {
		return ErrBadSignature
	}
	expectedBytes, _ := hex.DecodeString(expected)
	if !hmac.Equal(expectedBytes, provided) {
		return ErrBadSignature
	}
	return nil
}
