using System.Numerics;
using CupriCurve.Internal;
using Xunit;

namespace CupriCurve.Tests;

/// <summary>Exercises field ops whose operands are themselves Add/Sub results (un-normalized limbs).</summary>
public class FieldUnreducedTests
{
    private static readonly BigInteger P = BigInteger.Pow(2, 255) - 19;

    private static byte[] RandBytes(Random rng)
    {
        Span<byte> b = stackalloc byte[32];
        rng.NextBytes(b);
        b[31] &= 0x7F;
        BigInteger v = new BigInteger(b, isUnsigned: true, isBigEndian: false) % P;
        var arr = new byte[32];
        v.TryWriteBytes(arr, out _, isUnsigned: true, isBigEndian: false);
        return arr;
    }

    private static BigInteger FromBytes(ReadOnlySpan<byte> b) => new(b, isUnsigned: true, isBigEndian: false);
    private static byte[] ToBytes(Fe f) { var o = new byte[32]; f.ToBytes(o); return o; }
    private static byte[] ToBytes(BigInteger v) { var o = new byte[32]; (((v % P) + P) % P).TryWriteBytes(o, out _, isUnsigned: true, isBigEndian: false); return o; }

    [Fact]
    public void SubIsZero() => Assert.True(Fe.Sub(Fe.One, Fe.One).IsZero());

    [Fact]
    public void ChainedSub_IsZero() // e = (X+Y)^2 - A - B pattern with 0/1
    {
        Fe e = Fe.Sub(Fe.Sub(Fe.Sq(Fe.One), Fe.Zero), Fe.One);
        Assert.True(e.IsZero());
    }

    [Fact]
    public void NegZero_IsZero() => Assert.True(Fe.Neg(Fe.Zero).IsZero());

    [Fact]
    public void Mul_Of_Sub_Matches_BigInteger()
    {
        var rng = new Random(30);
        for (int i = 0; i < 3000; i++)
        {
            byte[] a = RandBytes(rng), b = RandBytes(rng), c = RandBytes(rng);
            Fe r = Fe.Mul(Fe.Sub(Fe.FromBytes(a), Fe.FromBytes(b)), Fe.FromBytes(c));
            BigInteger exp = ((FromBytes(a) - FromBytes(b)) * FromBytes(c));
            Assert.Equal(ToBytes(exp), ToBytes(r));
        }
    }

    [Fact]
    public void Mul_Of_Add_Matches_BigInteger()
    {
        var rng = new Random(31);
        for (int i = 0; i < 3000; i++)
        {
            byte[] a = RandBytes(rng), b = RandBytes(rng), c = RandBytes(rng);
            Fe r = Fe.Mul(Fe.Add(Fe.FromBytes(a), Fe.FromBytes(b)), Fe.FromBytes(c));
            BigInteger exp = ((FromBytes(a) + FromBytes(b)) * FromBytes(c));
            Assert.Equal(ToBytes(exp), ToBytes(r));
        }
    }

    [Fact]
    public void Double_Then_Mul_Chain() // mimics group intermediate magnitudes
    {
        var rng = new Random(32);
        for (int i = 0; i < 2000; i++)
        {
            byte[] a = RandBytes(rng), b = RandBytes(rng);
            Fe fa = Fe.FromBytes(a), fb = Fe.FromBytes(b);
            // (a+b)^2 - a^2 - b^2  should equal 2ab
            Fe lhs = Fe.Sub(Fe.Sub(Fe.Sq(Fe.Add(fa, fb)), Fe.Sq(fa)), Fe.Sq(fb));
            Fe rhs = Fe.Add(Fe.Mul(fa, fb), Fe.Mul(fa, fb));
            Assert.True(Fe.Equal(lhs, rhs), $"iter {i}");
        }
    }
}
