package httpauth

import (
	"github.com/1a11/clearintervals-edge/internal/config"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestPasswordWorkersSharedAndBounded(t *testing.T) {
	gate := New()
	gate.workers <- struct{}{}
	gate.workers <- struct{}{}
	defer func() { <-gate.workers; <-gate.workers }()
	r := httptest.NewRequest(http.MethodPost, "/", nil)
	r.SetBasicAuth("writer", "password")
	if _, status := gate.Authenticate(r, []config.Principal{{ID: "writer", PasswordHash: "unused"}}); status != 429 {
		t.Fatal(status)
	}
}
