package token

import (
	"encoding/base32"
	"encoding/hex"
	"fmt"
)

// accountForAKID is a best-effort method to extract the account ID from an AKID for
// logging on throttled requests. This should not be called on untrusted input (i.e.
// AKID from the request before validating the request from STS).
//
// This is not foolproof, but avoids an `sts:GetAccessKeyInfo` call per AKID.
// adapted from https://hackingthe.cloud/aws/enumeration/get-account-id-from-keys/
func accountForAKID(akid string) string {
	if len(akid) < 20 {
		// too short
		return ""
	}
	decoded, err := base32.StdEncoding.DecodeString(akid[4:])
	if err != nil {
		// decoding error
		return ""
	}
	y := decoded[:6]
	z := uint64(0)
	for i := 0; i < len(y); i++ {
		z = (z << 8) | uint64(y[i])
	}
	// this mask bytestring is always valid
	maskBytes, _ := hex.DecodeString("7fffffffff80")
	mask := uint64(0)
	for i := 0; i < len(maskBytes); i++ {
		mask = (mask << 8) | uint64(maskBytes[i])
	}
	// Apply mask and shift right by 7 bits
	e := (z & mask) >> 7
	return fmt.Sprintf("%012d", e)
}
