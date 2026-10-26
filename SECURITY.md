# Security support

The current v1 release is supported. Install patched images by their immutable digest after your site's change review. Automatic updates are disabled.

Report a suspected vulnerability privately through the repository's GitHub Security Advisory reporting channel. If private vulnerability reporting is unavailable, contact the Clear Intervals operator through your established support channel; do not post keys, tokens or customer data in an issue. Operators triage reports, publish patched digests and affected versions, and document any emergency protocol cutoff and deadline.

Verify release identity, provenance and SBOM as described in README.md. An arbitrary valid Sigstore signature is insufficient. Intermediate rollover retains the installed roots; a root change requires a verified local trust update. A compromised key requires revocation and a replacement enrollment bundle, not reuse of a copied state volume.
