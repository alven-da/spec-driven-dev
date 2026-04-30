package http

import (
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"strconv"
	"strings"
)

var errInvalidSessionCookie = errors.New("invalid session cookie")

type SessionCookieCodec struct {
	secret []byte
}

func NewSessionCookieCodec(secret string) *SessionCookieCodec {
	return &SessionCookieCodec{secret: []byte(secret)}
}

func (c *SessionCookieCodec) EncodeUserID(userID int64) string {
	payload := strconv.FormatInt(userID, 10)
	signature := c.sign(payload)
	return payload + "." + signature
}

func (c *SessionCookieCodec) DecodeUserID(raw string) (int64, error) {
	parts := strings.Split(raw, ".")
	if len(parts) != 2 {
		return 0, errInvalidSessionCookie
	}

	payload := parts[0]
	signature := parts[1]
	expected := c.sign(payload)
	if subtle.ConstantTimeCompare([]byte(signature), []byte(expected)) != 1 {
		return 0, errInvalidSessionCookie
	}

	userID, err := strconv.ParseInt(payload, 10, 64)
	if err != nil {
		return 0, errInvalidSessionCookie
	}
	return userID, nil
}

func (c *SessionCookieCodec) sign(payload string) string {
	mac := hmac.New(sha256.New, c.secret)
	_, _ = mac.Write([]byte(payload))
	return hex.EncodeToString(mac.Sum(nil))
}
