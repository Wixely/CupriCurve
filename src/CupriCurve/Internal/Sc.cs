using System.Numerics;

namespace CupriCurve.Internal;

/// <summary>
/// Scalar arithmetic modulo the Ed25519 group order L = 2^252 + 27742317777372353535851937790883648493.
/// Reduction and multiply-add are constant-time (see <see cref="ScRef10"/>); only the non-secret
/// canonical-range check uses <see cref="BigInteger"/>.
/// </summary>
internal static class Sc
{
    internal const int Size = 32;

    internal static readonly BigInteger L =
        BigInteger.Pow(2, 252) + BigInteger.Parse("27742317777372353535851937790883648493");

    private static BigInteger FromLe(ReadOnlySpan<byte> b) => new(b, isUnsigned: true, isBigEndian: false);

    /// <summary>Reduce a wide little-endian integer (up to 64 bytes) modulo L into 32 bytes.</summary>
    internal static void Reduce(ReadOnlySpan<byte> wide, Span<byte> out32)
    {
        if (wide.Length == 64)
        {
            ScRef10.Reduce(wide, out32);
            return;
        }
        // Zero-extend shorter inputs to 64 bytes for the fixed-width reducer.
        Span<byte> buf = stackalloc byte[64];
        buf.Clear();
        wide.Slice(0, Math.Min(wide.Length, 64)).CopyTo(buf);
        ScRef10.Reduce(buf, out32);
    }

    /// <summary>(a*b + c) mod L.</summary>
    internal static void MulAdd(ReadOnlySpan<byte> a, ReadOnlySpan<byte> b, ReadOnlySpan<byte> c, Span<byte> out32)
    {
        ScRef10.MulAdd(a, b, c, out32);
    }

    internal static bool IsCanonical(ReadOnlySpan<byte> s32) => FromLe(s32) < L;

    internal static void Clamp(Span<byte> scalar32)
    {
        scalar32[0] &= 248;
        scalar32[31] &= 127;
        scalar32[31] |= 64;
    }
}
