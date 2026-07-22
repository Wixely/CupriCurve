using CupriCurve.Internal;

namespace CupriCurve;

/// <summary>
/// Arithmetic on Ed25519 scalars modulo the group order
/// L = 2^252 + 27742317777372353535851937790883648493.
/// Scalars are 32-byte little-endian, matching RFC 8032.
/// </summary>
public static class Ed25519Scalar
{
    /// <summary>Length of a scalar in bytes.</summary>
    public const int Size = Sc.Size;

    /// <summary>Reduce a wide little-endian value (e.g. a 64-byte hash) modulo L into 32 bytes.</summary>
    public static void Reduce(ReadOnlySpan<byte> wide, Span<byte> out32)
    {
        ArgumentOutOfRangeException.ThrowIfLessThan(out32.Length, Size);
        Sc.Reduce(wide, out32.Slice(0, Size));
    }

    /// <summary>Compute (a*b + c) mod L.</summary>
    public static void MulAdd(ReadOnlySpan<byte> a, ReadOnlySpan<byte> b, ReadOnlySpan<byte> c, Span<byte> out32)
    {
        ArgumentOutOfRangeException.ThrowIfLessThan(out32.Length, Size);
        Sc.MulAdd(a, b, c, out32.Slice(0, Size));
    }

    /// <summary>RFC 8032 scalar clamping (clears the low 3 bits, sets bit 254, clears bit 255).</summary>
    public static void Clamp(Span<byte> scalar32)
    {
        ArgumentOutOfRangeException.ThrowIfLessThan(scalar32.Length, Size);
        Sc.Clamp(scalar32);
    }

    /// <summary>True if the 32-byte scalar is canonically reduced (strictly less than L).</summary>
    public static bool IsCanonical(ReadOnlySpan<byte> scalar32)
    {
        ArgumentOutOfRangeException.ThrowIfNotEqual(scalar32.Length, Size);
        return Sc.IsCanonical(scalar32);
    }
}
