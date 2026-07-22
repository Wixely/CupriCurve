using System.Numerics;

namespace CupriCurve.Internal;

/// <summary>
/// Scalar arithmetic modulo the Ed25519 group order L = 2^252 + 27742317777372353535851937790883648493.
///
/// NOTE (security): this first implementation uses <see cref="BigInteger"/>, which is correct but
/// NOT constant-time. It is adequate for public scalars (blinding factors, verification) but the
/// secret-scalar paths (private-key blinding) require a constant-time replacement before release.
/// Tracked as the immediate hardening follow-up; the differential tests already pin the expected
/// behaviour so a constant-time rewrite can be validated against it.
/// </summary>
internal static class Sc
{
    internal const int Size = 32;

    internal static readonly BigInteger L =
        BigInteger.Pow(2, 252) + BigInteger.Parse("27742317777372353535851937790883648493");

    private static BigInteger FromLe(ReadOnlySpan<byte> b) => new(b, isUnsigned: true, isBigEndian: false);

    private static void ToLe(BigInteger v, Span<byte> outb)
    {
        outb.Clear();
        Span<byte> tmp = stackalloc byte[64];
        if (v.TryWriteBytes(tmp, out int written, isUnsigned: true, isBigEndian: false))
        {
            tmp.Slice(0, Math.Min(written, outb.Length)).CopyTo(outb);
        }
        else
        {
            byte[] arr = v.ToByteArray(isUnsigned: true, isBigEndian: false);
            arr.AsSpan(0, Math.Min(arr.Length, outb.Length)).CopyTo(outb);
        }
    }

    /// <summary>Reduce a wide little-endian integer (up to 64 bytes) modulo L into 32 bytes.</summary>
    internal static void Reduce(ReadOnlySpan<byte> wide, Span<byte> out32)
    {
        BigInteger v = FromLe(wide) % L;
        ToLe(v, out32);
    }

    /// <summary>(a*b + c) mod L.</summary>
    internal static void MulAdd(ReadOnlySpan<byte> a, ReadOnlySpan<byte> b, ReadOnlySpan<byte> c, Span<byte> out32)
    {
        BigInteger v = (FromLe(a) * FromLe(b) + FromLe(c)) % L;
        ToLe(v, out32);
    }

    internal static bool IsCanonical(ReadOnlySpan<byte> s32) => FromLe(s32) < L;

    internal static void Clamp(Span<byte> scalar32)
    {
        scalar32[0] &= 248;
        scalar32[31] &= 127;
        scalar32[31] |= 64;
    }
}
