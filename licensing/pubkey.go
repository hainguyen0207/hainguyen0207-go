package licensing

import (
	"crypto/ed25519"
	"encoding/base64"
)

// publicKeyB64 is the vendor's Ed25519 public key, embedded in the product
// binary. It verifies license codes offline. The matching PRIVATE key is held
// only by the vendor (never committed, never shipped) and is used by the
// gen-license CLI to issue codes.
//
// To rotate: run `gen-license keygen`, replace this value with the printed
// public key, and keep the new private key offline.
const publicKeyB64 = "GsUDDr1ERbarw230gZqutaEJRzQ6Psc4UbSS77vsKfQ="

func embeddedPublicKey() ed25519.PublicKey {
	b, err := base64.StdEncoding.DecodeString(publicKeyB64)
	if err != nil || len(b) != ed25519.PublicKeySize {
		return nil
	}
	return ed25519.PublicKey(b)
}
