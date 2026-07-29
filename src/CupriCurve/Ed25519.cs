using System.Security.Cryptography;
using CupriCurve.Internal;

namespace CupriCurve;

/// <summary>
/// Ed25519 signing and verification (RFC 8032). Signing uses an expanded (scalar, prefix) key: standard
/// libraries only accept a 32-byte seed, but blinding produces a raw expanded key with a non-clamped scalar,
/// so <see cref="SignWithExpandedKey"/> is required to sign under a blinded identity. <see cref="Verify"/>
/// provides the standard RFC 8032 verifier, so the library both produces and checks signatures with no
/// external Ed25519 dependency.
/// </summary>
public static class Ed25519
{
    /// <summary>Signature length in bytes.</summary>
    public const int SignatureSize = 64;

    /// <summary>
    /// Produce an RFC 8032 Ed25519 signature over <paramref name="message"/> using the expanded key
    /// <paramref name="key"/> and its public key <paramref name="publicKey"/>.
    /// </summary>
    public static void SignWithExpandedKey(
        in Ed25519ExpandedKey key,
        ReadOnlySpan<byte> publicKey,
        ReadOnlySpan<byte> message,
        Span<byte> outSignature64)
    {
        ArgumentOutOfRangeException.ThrowIfNotEqual(publicKey.Length, 32);
        ArgumentOutOfRangeException.ThrowIfLessThan(outSignature64.Length, SignatureSize);

        ReadOnlySpan<byte> a = key.Scalar;
        ReadOnlySpan<byte> prefix = key.Prefix;

        // r = H(prefix || message) mod L
        Span<byte> wide = stackalloc byte[64];
        Hashing.Sha512(prefix, message, wide);
        Span<byte> r = stackalloc byte[32];
        Sc.Reduce(wide, r);

        // R = [r]B
        Span<byte> rPoint = outSignature64.Slice(0, 32);
        Ed25519Point.ScalarMultBase(r, rPoint);

        // k = H(R || A || message) mod L
        Hashing.Sha512(rPoint, publicKey, message, wide);
        Span<byte> k = stackalloc byte[32];
        Sc.Reduce(wide, k);

        // S = (r + k*a) mod L
        Span<byte> s = outSignature64.Slice(32, 32);
        Sc.MulAdd(k, a, r, s);
    }

    /// <summary>
    /// Verify an RFC 8032 Ed25519 <paramref name="signature"/> (R‖S) over <paramref name="message"/> against
    /// <paramref name="publicKey"/>. Returns false for any invalid or malformed input — wrong lengths, a
    /// non-canonical S (≥ L), an undecodable or small-order public key, a non-canonical R, or a failed group
    /// equation. It never throws on attacker-controlled data: verification fails closed. Uses the strict
    /// (non-cofactored) equation <c>[S]B = R + [k]A</c>; operates only on public data, so variable-time is fine.
    /// </summary>
    /// <param name="publicKey">The 32-byte public key A.</param>
    /// <param name="message">The signed message (any length).</param>
    /// <param name="signature">The 64-byte signature R‖S.</param>
    public static bool Verify(ReadOnlySpan<byte> publicKey, ReadOnlySpan<byte> message, ReadOnlySpan<byte> signature)
    {
        if (publicKey.Length != 32 || signature.Length != SignatureSize)
            return false;

        ReadOnlySpan<byte> rBytes = signature[..32];
        ReadOnlySpan<byte> s = signature[32..];

        // 1. S must be canonical (0 <= S < L). Rejects trivially-malleated signatures (S += L).
        if (!Sc.IsCanonical(s))
            return false;

        // 2. Decode A; reject undecodable or (hardening, matching libsodium) small-order public keys.
        if (!Ge.TryDecode(publicKey, out Ge a))
            return false;
        if (Ge.Double(Ge.Double(Ge.Double(a))).IsIdentity()) // [8]A == identity ⇒ small order
            return false;

        // 3. k = SHA-512(R || A || M) reduced mod L.
        Span<byte> wide = stackalloc byte[64];
        Hashing.Sha512(rBytes, publicKey, message, wide);
        Span<byte> k = stackalloc byte[32];
        Sc.Reduce(wide, k);

        // 4. Strict RFC 8032 equation [S]B == R + [k]A, rearranged to [S]B + [k](-A) == R. We compare the
        //    *encoding* of the computed left-hand side to the R bytes and never decode R as a point, so a
        //    non-canonical R also fails here. In extended coordinates, -P = (-X, Y, Z, -T).
        var negA = new Ge(Fe.Neg(a.X), a.Y, a.Z, Fe.Neg(a.T));
        Ge rCheck = Ge.Add(Ge.ScalarMultBase(s), Ge.ScalarMult(k, negA));

        Span<byte> rCheckBytes = stackalloc byte[32];
        rCheck.ToBytes(rCheckBytes);
        return CryptographicOperations.FixedTimeEquals(rCheckBytes, rBytes);
    }

    /// <summary>
    /// Sign <paramref name="message"/> from a 32-byte seed: expands it to the (scalar, prefix) key, derives the
    /// public key, then signs (RFC 8032). Convenience over <see cref="Ed25519ExpandedKey.FromSeed"/> +
    /// <see cref="Ed25519ExpandedKey.GetPublicKey"/> + <see cref="SignWithExpandedKey"/>.
    /// </summary>
    public static void SignWithSeed(ReadOnlySpan<byte> seed32, ReadOnlySpan<byte> message, Span<byte> outSignature64)
    {
        Ed25519ExpandedKey key = Ed25519ExpandedKey.FromSeed(seed32);
        Span<byte> pub = stackalloc byte[32];
        key.GetPublicKey(pub);
        SignWithExpandedKey(key, pub, message, outSignature64);
    }

    /// <summary>Derive the 32-byte Ed25519 public key A = [a]B for a 32-byte seed (RFC 8032 expansion).</summary>
    public static void PublicKeyFromSeed(ReadOnlySpan<byte> seed32, Span<byte> outPublicKey32)
    {
        Ed25519ExpandedKey.FromSeed(seed32).GetPublicKey(outPublicKey32);
    }
}
