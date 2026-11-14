package licensing

import (
	"strings"
	"testing"
	"time"
)

// The real issued code from the CLI round-trip (perpetual, any-machine, pro).
const sampleCode = "eyJjdXN0b21lciI6IlRlc3QgQ3VzdG9tZXIiLCJ0aWVyIjoicHJvIiwiaWF0IjoxNzk0NjUxNjg2LCJsaW1pdHMiOnt9LCJub25jZSI6Ik4zRHBudlhUUGg4In0.K3tse8L47dWHDZzMxzBbFo8YiPqI3lRqOeafq9T4bSfmb0h-EIZ9ykDXfPsi_kB8g0L8E2KZCradPw3QkFnACg"

func TestVerifyGenuine(t *testing.T) {
	c, err := Verify(sampleCode)
	if err != nil {
		t.Fatalf("Verify genuine: %v", err)
	}
	if c.Customer != "Test Customer" || c.Tier != "pro" {
		t.Fatalf("claims mismatch: %+v", c)
	}
	if err := c.Check(time.Now(), "anything"); err != nil {
		t.Fatalf("Check any-machine perpetual: %v", err)
	}
	if !c.Allows("whatever") {
		t.Fatal("empty features should allow all")
	}
}

func TestVerifyTampered(t *testing.T) {
	// Flip the last char of the payload segment.
	parts := strings.SplitN(sampleCode, ".", 2)
	bad := parts[0][:len(parts[0])-1] + "X." + parts[1]
	if _, err := Verify(bad); err == nil {
		t.Fatal("tampered payload should fail verification")
	}
}

func TestExpired(t *testing.T) {
	c := Claims{ExpiresAt: time.Now().Add(-time.Hour).Unix()}
	if err := c.Check(time.Now(), "m"); err == nil {
		t.Fatal("expired license should fail Check")
	}
}

func TestMachineBound(t *testing.T) {
	c := Claims{MachineID: "AAAA"}
	if err := c.Check(time.Now(), "BBBB"); err == nil {
		t.Fatal("wrong machine should fail Check")
	}
	if err := c.Check(time.Now(), "aaaa"); err != nil {
		t.Fatalf("matching machine (case-insensitive) should pass: %v", err)
	}
}
