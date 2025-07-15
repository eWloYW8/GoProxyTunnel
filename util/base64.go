package util

import (
	"encoding/base64"
)

// EncodeBase64 is a helper function for encoding strings to Base64.
func EncodeBase64(s string) string {
	return base64.StdEncoding.EncodeToString([]byte(s))
}
