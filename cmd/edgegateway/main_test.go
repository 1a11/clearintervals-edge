package main

import (
	"testing"
	"time"

	"github.com/1a11/clearintervals-edge/internal/uplink"
)

func TestCapacityRetryRecoversFromPriorConnectionBackoff(t *testing.T) {
	if got := retryBackoff(8*time.Minute, &uplink.Failure{Code: "invalid_session", Retry: 5 * time.Second}); got != 5*time.Second {
		t.Fatalf("closed epoch recovery delayed by old connection failures: %s", got)
	}
	if got := retryBackoff(8*time.Minute, &uplink.Failure{Code: "rate_limited", Retry: 5 * time.Second}); got != 5*time.Second {
		t.Fatalf("capacity recovery delayed by old connection failures: %s", got)
	}
	if got := retryBackoff(time.Minute, &uplink.Failure{Code: "rate_limited", Retry: 90 * time.Second}); got != 90*time.Second {
		t.Fatalf("server retry floor ignored: %s", got)
	}
	if got := retryBackoff(time.Minute, &uplink.Failure{Code: "core_unavailable", Retry: 5 * time.Second}); got != time.Minute {
		t.Fatalf("outage backoff lost: %s", got)
	}
}

func TestWelcomedSessionClearsPriorOutagePenalty(t *testing.T) {
	if got := sessionBackoff(8*time.Minute, true); got != 5*time.Second {
		t.Fatalf("recovered session retains outage penalty: %s", got)
	}
	if got := sessionBackoff(8*time.Minute, false); got != 8*time.Minute {
		t.Fatalf("failed admission loses outage backoff: %s", got)
	}
}

func TestRepeatedAdmissionPressureBacksOffWithoutOldOutagePenalty(t *testing.T) {
	failure := &uplink.Failure{Code: "rate_limited", Retry: 5 * time.Second}
	streak := time.Duration(0)
	for _, expected := range []time.Duration{5, 10, 20, 40, 60, 60} {
		wait, next := capacityRetry(streak, failure)
		if wait != expected*time.Second {
			t.Fatalf("admission retry=%s expected=%s", wait, expected*time.Second)
		}
		streak = next
	}
	wait, _ := capacityRetry(0, &uplink.Failure{Code: "rate_limited", Retry: 2 * time.Minute})
	if wait != 2*time.Minute {
		t.Fatal("server retry floor lost")
	}
}
