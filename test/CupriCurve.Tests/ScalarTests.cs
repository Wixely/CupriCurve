using System.Numerics;
using CupriCurve.Internal;
using Xunit;

namespace CupriCurve.Tests;

/// <summary>Differential tests of the constant-time scalar arithmetic (ScRef10) against a BigInteger oracle.</summary>
public class ScalarTests
{
    private static readonly BigInteger L =
        BigInteger.Pow(2, 252) + BigInteger.Parse("27742317777372353535851937790883648493");

    private static BigInteger FromLe(ReadOnlySpan<byte> b) => new(b, isUnsigned: true, isBigEndian: false);

    private static byte[] ToLe32(BigInteger v)
    {
        v = ((v % L) + L) % L;
        var o = new byte[32];
        v.TryWriteBytes(o, out _, isUnsigned: true, isBigEndian: false);
        return o;
    }

    [Fact]
    public void Reduce_Matches_Oracle_Random64()
    {
        var rng = new Random(40);
        var wide = new byte[64];
        var outb = new byte[32];
        for (int i = 0; i < 20000; i++)
        {
            rng.NextBytes(wide);
            ScRef10.Reduce(wide, outb);
            Assert.Equal(ToLe32(FromLe(wide)), outb);
        }
    }

    [Fact]
    public void MulAdd_Matches_Oracle_Random32()
    {
        var rng = new Random(41);
        var a = new byte[32];
        var b = new byte[32];
        var c = new byte[32];
        var outb = new byte[32];
        for (int i = 0; i < 20000; i++)
        {
            rng.NextBytes(a);
            rng.NextBytes(b);
            rng.NextBytes(c);
            ScRef10.MulAdd(a, b, c, outb);
            Assert.Equal(ToLe32(FromLe(a) * FromLe(b) + FromLe(c)), outb);
        }
    }

    [Fact]
    public void EdgeCases()
    {
        var outb = new byte[32];

        // Reduce of exactly L, L-1, L+1, 0, 2^512-1
        foreach (BigInteger v in new[] { L, L - 1, L + 1, BigInteger.Zero, BigInteger.Pow(2, 512) - 1 })
        {
            var wide = new byte[64];
            (((v) % BigInteger.Pow(2, 512))).TryWriteBytes(wide, out _, isUnsigned: true, isBigEndian: false);
            ScRef10.Reduce(wide, outb);
            Assert.Equal(ToLe32(FromLe(wide)), outb);
        }

        // MulAdd with clamped-scalar-like operand (bit 254 set => value > L)
        var big = new byte[32];
        big[0] = 248; big[31] = 64 | 63; // ~2^254 clamped shape
        var one = new byte[32]; one[0] = 1;
        var zero = new byte[32];
        ScRef10.MulAdd(big, one, zero, outb);
        Assert.Equal(ToLe32(FromLe(big)), outb);
    }
}
