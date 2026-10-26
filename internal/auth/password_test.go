package auth

import (
	"strings"
	"testing"
)

func TestBoundedSaltedPasswordProfile(t *testing.T) {
	password := strings.Repeat("a", 43)
	hash, e := Hash(password)
	if e != nil {
		t.Fatal(e)
	}
	if !Verify(hash, password) || Verify(hash, strings.Repeat("b", 43)) {
		t.Fatal("password verification")
	}
	second, e := Hash(password)
	if e != nil || hash == second {
		t.Fatal("password salt reused")
	}
	for _, bad := range []string{strings.Replace(hash, "m=65536", "m=1073741824", 1), strings.Replace(hash, "p=1", "p=64", 1), hash + "$extra", "plaintext"} {
		if _, _, e = Parse(bad); e == nil {
			t.Fatal("unbounded profile accepted")
		}
	}
}
func BenchmarkPasswordVerify(b *testing.B) {
	password := strings.Repeat("a", 43)
	hash, e := Hash(password)
	if e != nil {
		b.Fatal(e)
	}
	b.ResetTimer()
	for b.Loop() {
		if !Verify(hash, password) {
			b.Fatal("verification")
		}
	}
}
