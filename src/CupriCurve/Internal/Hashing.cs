using System.Security.Cryptography;

namespace CupriCurve.Internal;

/// <summary>
/// SHA-512 helper. Uses the in-box BCL implementation (no extra package dependency).
/// Hashing operates only on public or already-committed data, so timing is not the
/// constant-time concern here — the scalar/field arithmetic is.
/// </summary>
internal static class Hashing
{
    internal static void Sha512(ReadOnlySpan<byte> a, Span<byte> out64)
    {
        using var sha = SHA512.Create();
        sha.TryComputeHash(a, out64, out _);
    }

    internal static void Sha512(ReadOnlySpan<byte> a, ReadOnlySpan<byte> b, Span<byte> out64)
    {
        using var sha = IncrementalHash.CreateHash(HashAlgorithmName.SHA512);
        sha.AppendData(a);
        sha.AppendData(b);
        sha.GetHashAndReset(out64);
    }

    internal static void Sha512(ReadOnlySpan<byte> a, ReadOnlySpan<byte> b, ReadOnlySpan<byte> c, Span<byte> out64)
    {
        using var sha = IncrementalHash.CreateHash(HashAlgorithmName.SHA512);
        sha.AppendData(a);
        sha.AppendData(b);
        sha.AppendData(c);
        sha.GetHashAndReset(out64);
    }
}
