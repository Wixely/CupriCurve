using CupriCurve.Internal;

namespace CupriCurve;

/// <summary>
/// A decoded, validated Ed25519 curve point. Obtain one via <see cref="Ed25519Point.TryDecode"/>
/// and reuse it to avoid repeated decompression.
/// </summary>
public readonly struct Ed25519PointHandle
{
    internal readonly Ge Point;
    internal readonly bool Valid;
    internal Ed25519PointHandle(in Ge p) { Point = p; Valid = true; }
}

/// <summary>
/// Low-level Ed25519 group operations: point decompression/compression, scalar multiplication by
/// the base point or an arbitrary point, and small-order detection. Scalars are 32-byte little-endian.
/// </summary>
public static class Ed25519Point
{
    /// <summary>Length of a compressed point in bytes.</summary>
    public const int Size = 32;

    /// <summary>Decode a compressed point. Returns false for non-canonical or off-curve encodings.</summary>
    public static bool TryDecode(ReadOnlySpan<byte> point32, out Ed25519PointHandle handle)
    {
        handle = default;
        if (point32.Length != Size) return false;
        if (!Ge.TryDecode(point32, out Ge p)) return false;
        handle = new Ed25519PointHandle(p);
        return true;
    }

    /// <summary>Encode a decoded point to 32 compressed bytes.</summary>
    public static void Encode(in Ed25519PointHandle handle, Span<byte> out32)
    {
        if (!handle.Valid) throw new ArgumentException("Point handle is not initialized.", nameof(handle));
        ArgumentOutOfRangeException.ThrowIfLessThan(out32.Length, Size);
        handle.Point.ToBytes(out32.Slice(0, Size));
    }

    /// <summary>Compute [scalar]B, the compressed public key for a scalar (base-point multiplication).</summary>
    public static void ScalarMultBase(ReadOnlySpan<byte> scalar32, Span<byte> out32)
    {
        ArgumentOutOfRangeException.ThrowIfNotEqual(scalar32.Length, Ed25519Scalar.Size);
        ArgumentOutOfRangeException.ThrowIfLessThan(out32.Length, Size);
        Ge r = Ge.ScalarMultBase(scalar32);
        r.ToBytes(out32.Slice(0, Size));
    }

    /// <summary>Compute [scalar]P for an arbitrary compressed point. Returns false if the point is invalid.</summary>
    public static bool TryScalarMult(ReadOnlySpan<byte> scalar32, ReadOnlySpan<byte> point32, Span<byte> out32)
    {
        ArgumentOutOfRangeException.ThrowIfNotEqual(scalar32.Length, Ed25519Scalar.Size);
        ArgumentOutOfRangeException.ThrowIfLessThan(out32.Length, Size);
        if (!Ge.TryDecode(point32, out Ge p)) return false;
        Ge r = Ge.ScalarMult(scalar32, p);
        r.ToBytes(out32.Slice(0, Size));
        return true;
    }

    /// <summary>Compute [scalar]P for a pre-decoded point.</summary>
    public static void ScalarMult(ReadOnlySpan<byte> scalar32, in Ed25519PointHandle point, Span<byte> out32)
    {
        if (!point.Valid) throw new ArgumentException("Point handle is not initialized.", nameof(point));
        ArgumentOutOfRangeException.ThrowIfNotEqual(scalar32.Length, Ed25519Scalar.Size);
        ArgumentOutOfRangeException.ThrowIfLessThan(out32.Length, Size);
        Ge r = Ge.ScalarMult(scalar32, point.Point);
        r.ToBytes(out32.Slice(0, Size));
    }

    /// <summary>True if the point has small order (order dividing the cofactor 8), i.e. [8]P is the identity.</summary>
    public static bool IsSmallOrder(ReadOnlySpan<byte> point32)
    {
        if (!Ge.TryDecode(point32, out Ge p)) return false;
        Ge q = Ge.Double(Ge.Double(Ge.Double(p)));
        return q.IsIdentity();
    }
}
