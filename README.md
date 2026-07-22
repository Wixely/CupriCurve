# CupriCurve

Constant-time, **100% managed**, **MIT-licensed**, **.NET 10** Curve25519/Ed25519 field and group arithmetic —
exposing the low-level operations that standard signing APIs hide, including **Tor-style Ed25519 key blinding**
(scalar-mult by an arbitrary scalar/point, scalar arithmetic mod `L`, point encode/decode and torsion checks).

Built to unblock [CupriTor](https://github.com/Wixely/CupriTor)'s v3 onion-service key blinding, but generic and
protocol-agnostic: it knows no Tor constants — callers pass in the finished blinding scalar.

> Status: early / planning. See the local `plan/` folder (git-ignored) for the full spec and test-vector acceptance bar.

## License

MIT.
