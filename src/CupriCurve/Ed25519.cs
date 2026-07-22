using CupriCurve.Internal;

namespace CupriCurve;

/// <summary>
/// Ed25519 signing using an expanded (scalar, prefix) key. Standard signing libraries only accept
/// a 32-byte seed; blinding produces a raw expanded key with a non-clamped scalar, so this entry
/// point is required to sign under a blinded identity. Verification is standard RFC 8032 and can be
/// performed by any conforming verifier against the (blinded) public key.
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
}
