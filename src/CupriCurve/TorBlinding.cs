using CupriCurve.Internal;

namespace CupriCurve;

/// <summary>
/// Tor-style Ed25519 key blinding: derive a per-period keypair from an identity keypair and a
/// blinding scalar <c>h</c>. The public key blinds as A' = [h]A and the private scalar as
/// a' = h*a mod L.
///
/// This library is deliberately protocol-agnostic: it does NOT know how <c>h</c> is derived (that
/// is Tor's <c>rend-spec-v3</c> string/period logic, which lives in the caller). The caller passes
/// the finished, already-reduced blinding scalar and, for the private path, the personalization
/// bytes used to derive the new nonce prefix.
/// </summary>
public static class TorBlinding
{
    /// <summary>Blind a public key: A' = [h]A. Returns false if <paramref name="publicKey32"/> is not a valid point.</summary>
    public static bool TryBlindPublicKey(ReadOnlySpan<byte> publicKey32, ReadOnlySpan<byte> blindingScalar32, Span<byte> outBlindedPublic32)
    {
        ArgumentOutOfRangeException.ThrowIfNotEqual(blindingScalar32.Length, 32);
        ArgumentOutOfRangeException.ThrowIfLessThan(outBlindedPublic32.Length, 32);
        return Ed25519Point.TryScalarMult(blindingScalar32, publicKey32, outBlindedPublic32);
    }

    /// <summary>
    /// Blind an expanded private key. Produces the blinded scalar a' = h*a mod L and a new nonce
    /// prefix RH' = SHA-512(<paramref name="prefixPersonalization"/> || RH)[0..32].
    /// </summary>
    public static void BlindPrivateKey(
        in Ed25519ExpandedKey key,
        ReadOnlySpan<byte> blindingScalar32,
        ReadOnlySpan<byte> prefixPersonalization,
        Span<byte> outBlindedScalar32,
        Span<byte> outBlindedPrefix32)
    {
        ArgumentOutOfRangeException.ThrowIfNotEqual(blindingScalar32.Length, 32);
        ArgumentOutOfRangeException.ThrowIfLessThan(outBlindedScalar32.Length, 32);
        ArgumentOutOfRangeException.ThrowIfLessThan(outBlindedPrefix32.Length, 32);

        // a' = h*a + 0 mod L
        Span<byte> zero = stackalloc byte[32];
        Sc.MulAdd(blindingScalar32, key.Scalar, zero, outBlindedScalar32.Slice(0, 32));

        // RH' = H(personalization || RH)[0..32]
        Span<byte> wide = stackalloc byte[64];
        Hashing.Sha512(prefixPersonalization, key.Prefix, wide);
        wide.Slice(0, 32).CopyTo(outBlindedPrefix32);
    }
}
