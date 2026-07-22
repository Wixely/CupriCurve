# Security policy

CupriCurve implements low-level elliptic-curve arithmetic used for anonymity-critical operations
(Tor v3 onion-service key blinding). Bugs here can be deanonymizing, not merely incorrect.

## Scope and guarantees

- **Constant-time:** field arithmetic (`Fe`), group operations / scalar multiplication (`Ge`), and
  scalar reduction / multiply-add (`ScRef10`) are written to avoid secret-dependent branches and
  memory access. Point *decompression* and the non-secret `IsCanonical` range check are not required
  to be constant-time (they operate on public data).
- **Validated:** field arithmetic is differential-tested against `BigInteger`; public keys, signatures,
  and blinded-signature verification are cross-checked against BouncyCastle (itself RFC 8032-validated);
  scalar arithmetic is checked against a `BigInteger` oracle over tens of thousands of cases.
- **Dependencies:** none beyond the .NET base class library. AOT-compatible.

## Not yet done (before a 1.0 tag)

- A formal constant-time audit and a statistical timing smoke-test.
- Independent review of the blinding path against published Tor test vectors.

## Reporting

Report suspected vulnerabilities privately to the maintainer (Wixely) rather than via public issues.
