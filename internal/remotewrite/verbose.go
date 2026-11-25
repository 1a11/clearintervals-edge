package remotewrite

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"net/http"
	"sort"
	"strings"
	"time"

	"github.com/1a11/clearintervals-edge/internal/config"
)

// bearerDigest is the SHA-256 of the presented bearer token, or empty when the request carried none.
func bearerDigest(r *http.Request) string {
	auth := r.Header.Get("Authorization")
	if !strings.HasPrefix(auth, "Bearer ") {
		return ""
	}
	sum := sha256.Sum256([]byte(strings.TrimPrefix(auth, "Bearer ")))
	return hex.EncodeToString(sum[:])
}

// authComparisons shows, for every configured principal, the digest the gateway computed from this request and
// whether it equals the configured one. It is the fastest way to see a mistyped or rotated writer token.
func authComparisons(principals []config.Principal, r *http.Request) []map[string]any {
	auth := r.Header.Get("Authorization")
	var tokenHash, certHash [32]byte
	hasToken := strings.HasPrefix(auth, "Bearer ")
	if hasToken {
		tokenHash = sha256.Sum256([]byte(strings.TrimPrefix(auth, "Bearer ")))
	}
	hasCert := r.TLS != nil && len(r.TLS.PeerCertificates) > 0
	if hasCert {
		certHash = sha256.Sum256(r.TLS.PeerCertificates[0].Raw)
	}
	out := make([]map[string]any, 0, len(principals))
	for _, p := range principals {
		entry := map[string]any{
			"id": p.ID, "tokenSha256": p.TokenSHA256, "certificateSha256": p.CertificateSHA256,
			"passwordHashSet": p.PasswordHash != "",
		}
		if hasToken && p.TokenSHA256 != "" {
			expected, _ := hex.DecodeString(p.TokenSHA256)
			entry["tokenMatch"] = subtle.ConstantTimeCompare(tokenHash[:], expected) == 1
		}
		if hasCert && p.CertificateSHA256 != "" {
			expected, _ := hex.DecodeString(p.CertificateSHA256)
			entry["certificateMatch"] = subtle.ConstantTimeCompare(certHash[:], expected) == 1
		}
		out = append(out, entry)
	}
	return out
}

// bindingDiffs explains an unmapped series one active binding at a time: which selector label was absent from the
// received labels and which one carried a different value.
func bindingDiffs(bindings []config.Binding, labels map[string]string) []map[string]any {
	out := []map[string]any{}
	for _, b := range bindings {
		if b.Kind != "series" {
			continue
		}
		missing := []string{}
		mismatched := []map[string]any{}
		for label, expected := range b.Selector {
			received, present := labels[label]
			switch {
			case !present:
				missing = append(missing, label)
			case received != expected:
				mismatched = append(mismatched, map[string]any{"label": label, "expected": expected, "received": received})
			}
		}
		if len(missing) == 0 && len(mismatched) == 0 {
			continue
		}
		sort.Strings(missing)
		sort.Slice(mismatched, func(i, j int) bool {
			return mismatched[i]["label"].(string) < mismatched[j]["label"].(string)
		})
		out = append(out, map[string]any{
			"bindingId": b.ID, "selector": b.Selector, "missingLabels": missing, "mismatchedLabels": mismatched,
		})
	}
	return out
}

// sampleValues renders the raw timestamps and values a writer sent.
func sampleValues(samples []sample) []map[string]any {
	out := make([]map[string]any, 0, len(samples))
	for _, v := range samples {
		at := time.UnixMilli(v.at).UTC()
		out = append(out, map[string]any{"timestampMs": v.at, "timestamp": at.Format(time.RFC3339Nano), "value": v.value})
	}
	return out
}

func bindingIDs(bindings []config.Binding) []string {
	out := make([]string, 0, len(bindings))
	for _, b := range bindings {
		out = append(out, b.ID)
	}
	return out
}

// headerMap is the request's headers as a plain map, Authorization included: verbose output is for the operator
// debugging their own writer, and the credential in the header is what they need to compare.
func headerMap(r *http.Request) map[string]string {
	out := make(map[string]string, len(r.Header))
	for name, values := range r.Header {
		out[name] = strings.Join(values, ", ")
	}
	return out
}

func basicUser(r *http.Request) string {
	user, _, ok := r.BasicAuth()
	if !ok {
		return ""
	}
	return user
}

// authReason explains a 401/429 without revealing whether a token, a password or the rate limiter was to blame
// beyond what the operator already knows about their own request.
func authReason(r *http.Request) string {
	authorization := r.Header.Get("Authorization")
	switch {
	case authorization == "":
		return "no Authorization header"
	case strings.HasPrefix(authorization, "Bearer "):
		if len(authorization) < 50 || len(authorization) > 256 {
			return "bearer token length is outside the accepted 43 to 251 bytes"
		}
		return "bearer token digest matches no principal tokenSha256"
	case strings.HasPrefix(strings.ToLower(authorization), "basic "):
		return "basic credentials match no principal passwordHash, or the password worker pool is saturated"
	}
	return "unsupported Authorization scheme"
}
