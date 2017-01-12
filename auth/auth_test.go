package auth

import (
	"bytes"
	"testing"
)

type TestAuth struct{}

func (t *TestAuth) Compute(v []byte) ([]byte, error) {
	x := make([]byte, len(v))
	for i, vv := range v {
		x[i] = vv ^ 131
	}
	return x, nil
}

func (t *TestAuth) Verify(challenge, attempt []byte) bool {
	x, _ := t.Compute(attempt)
	return bytes.Equal(challenge, x)
}

func TestDupRegister(t *testing.T) {
	if err := Register("duptest", &TestAuth{}); err != nil {
		t.Fatalf("unexpected error on initial registration: %q", err)
	}
	if err := Register("duptest", &TestAuth{}); err == nil {
		t.Fatal("expected error on second registration, got none")
	}
}

func TestNotRegistered(t *testing.T) {
	c := []byte("test challenge")
	a := []byte("test attempt")
	if _, err := Verify("NoSuchAuthType", c, a); !IsInvalidType(err) {
		t.Fatalf("Expected invalid type error in Verify, got %q", err)
	}
	if _, err := Compute("NoSuchAuthType", a); !IsInvalidType(err) {
		t.Fatalf("Expected invalid type error in Compute, got %q", err)
	}
}
