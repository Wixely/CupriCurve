using System.Security.Cryptography;
using CupriCurve.Internal;

namespace CupriCurve;

/// <summary>
/// An expanded Ed25519 private key: the clamped scalar <c>a</c> plus the 32-byte nonce prefix
/// <c>RH</c>, as produced by hashing a 32-byte seed with SHA-512 (RFC 8032). Tor key blinding
/// operates on this expanded form, not on the seed.
/// </summary>
public readonly struct Ed25519ExpandedKey
{
    private readonly byte[] _scalar; // clamped 'a'
    private readonly byte[] _prefix; // 'RH'

    private Ed25519ExpandedKey(byte[] scalar, byte[] prefix)
    {
        _scalar = scalar;
        _prefix = prefix;
    }

    /// <summary>Expand a 32-byte seed into (scalar, prefix) per RFC 8032.</summary>
    public static Ed25519ExpandedKey FromSeed(ReadOnlySpan<byte> seed32)
    {
        ArgumentOutOfRangeException.ThrowIfNotEqual(seed32.Length, 32);
        Span<byte> h = stackalloc byte[64];
        Hashing.Sha512(seed32, h);

        byte[] scalar = h.Slice(0, 32).ToArray();
        Sc.Clamp(scalar);
        byte[] prefix = h.Slice(32, 32).ToArray();
        CryptographicOperations.ZeroMemory(h);
        return new Ed25519ExpandedKey(scalar, prefix);
    }

    /// <summary>Construct directly from an existing clamped scalar and nonce prefix.</summary>
    public static Ed25519ExpandedKey FromParts(ReadOnlySpan<byte> scalar32, ReadOnlySpan<byte> prefix32)
    {
        ArgumentOutOfRangeException.ThrowIfNotEqual(scalar32.Length, 32);
        ArgumentOutOfRangeException.ThrowIfNotEqual(prefix32.Length, 32);
        return new Ed25519ExpandedKey(scalar32.ToArray(), prefix32.ToArray());
    }

    /// <summary>The clamped private scalar <c>a</c> (secret).</summary>
    public ReadOnlySpan<byte> Scalar => _scalar;

    /// <summary>The nonce prefix <c>RH</c> (secret).</summary>
    public ReadOnlySpan<byte> Prefix => _prefix;

    /// <summary>Compute the corresponding public key A = [a]B.</summary>
    public void GetPublicKey(Span<byte> out32)
    {
        ArgumentOutOfRangeException.ThrowIfLessThan(out32.Length, 32);
        Ed25519Point.ScalarMultBase(_scalar, out32);
    }
}
