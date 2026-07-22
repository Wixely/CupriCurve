using System.Numerics;
using CupriCurve.Internal;
using Xunit;

namespace CupriCurve.Tests;

/// <summary>Differential tests of the field arithmetic against a BigInteger reference mod p.</summary>
public class FieldTests
{
    private static readonly BigInteger P = BigInteger.Pow(2, 255) - 19;

    private static byte[] RandomFieldBytes(Random rng)
    {
        Span<byte> b = stackalloc byte[32];
        rng.NextBytes(b);
        b[31] &= 0x7F; // clear the top bit
        BigInteger v = new BigInteger(b, isUnsigned: true, isBigEndian: false) % P;
        return ToBytes(v);
    }

    private static byte[] ToBytes(BigInteger v)
    {
        var arr = new byte[32];
        v.TryWriteBytes(arr, out _, isUnsigned: true, isBigEndian: false);
        return arr;
    }

    private static BigInteger FromBytes(ReadOnlySpan<byte> b) => new(b, isUnsigned: true, isBigEndian: false);

    private static byte[] Enc(in Fe f) { var o = new byte[32]; f.ToBytes(o); return o; }

    [Fact]
    public void FromBytes_ToBytes_RoundTrips_Canonical()
    {
        var rng = new Random(1);
        for (int i = 0; i < 500; i++)
        {
            byte[] a = RandomFieldBytes(rng);
            Assert.Equal(a, Enc(Fe.FromBytes(a)));
        }
    }

    [Fact]
    public void Mul_Matches_BigInteger()
    {
        var rng = new Random(2);
        for (int i = 0; i < 2000; i++)
        {
            byte[] a = RandomFieldBytes(rng);
            byte[] b = RandomFieldBytes(rng);
            Fe r = Fe.Mul(Fe.FromBytes(a), Fe.FromBytes(b));
            BigInteger expected = (FromBytes(a) * FromBytes(b)) % P;
            Assert.Equal(ToBytes(expected), Enc(r));
        }
    }

    [Fact]
    public void AddSub_Match_BigInteger()
    {
        var rng = new Random(3);
        for (int i = 0; i < 2000; i++)
        {
            byte[] a = RandomFieldBytes(rng);
            byte[] b = RandomFieldBytes(rng);
            Fe fa = Fe.FromBytes(a), fb = Fe.FromBytes(b);

            Assert.Equal(ToBytes((FromBytes(a) + FromBytes(b)) % P), Enc(Fe.Add(fa, fb)));
            Assert.Equal(ToBytes(((FromBytes(a) - FromBytes(b)) % P + P) % P), Enc(Fe.Sub(fa, fb)));
        }
    }

    [Fact]
    public void Invert_Yields_One()
    {
        var rng = new Random(4);
        for (int i = 0; i < 200; i++)
        {
            byte[] a = RandomFieldBytes(rng);
            if (FromBytes(a).IsZero) continue;
            Fe prod = Fe.Mul(Fe.FromBytes(a), Fe.Invert(Fe.FromBytes(a)));
            Assert.True(Fe.Equal(prod, Fe.One));
        }
    }
}
