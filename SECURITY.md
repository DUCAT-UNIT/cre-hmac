# Security operations

## Permanently revoked credentials

An oracle private key and a Chainlink client secret were committed to public
history. They must be treated as permanently compromised, even after repository
history is cleaned. The source tree intentionally retains only the derived
public identity and SHA-256 fingerprints needed to reject those credentials at
runtime; it does not retain their secret values.

Current workflows fail closed if either revoked credential is loaded. The
repository test suite also rejects their reintroduction and literal
`DUCAT_PRIVATE_KEY` / `DUCAT_CLIENT_SECRET` assignments.

## Rotation sequence

1. Revoke and replace the exposed Chainlink client secret at the provider.
2. Generate a new random secp256k1 oracle key for each environment/role and put
   it directly in the CRE secret store. Never place it in a shell script,
   command allow-rule, test fixture, or repository file.
3. Derive each new oracle public key locally, add it to the corresponding relay
   write allowlist, and canary the workflow.
4. Remove the revoked public identity from every relay allowlist and redeploy
   every workflow that could have cached the old secrets.
5. Apply the sanitized code and credential-deny guards to every live public
   branch. A fix on only the default branch does not remove credential material
   from other branch tips.
6. Only after revocation is complete, coordinate a full history rewrite and
   force-push across all public refs. History cleanup is best-effort: existing
   clones and caches make rotation mandatory.

As a non-production check on 2026-08-06, the revoked public identity authored no
event returned by the Mutinynet staging, Mutinynet dev, or Testnet4 dev relays.
That is not proof of revocation or absence of historical use.

## Verification

Run `go test ./...` before every release. The `shared` package test scans tracked
and non-ignored files without printing matched credential values. CI also runs
race tests, host/WASI vetting, and builds all three deployable workflows.
