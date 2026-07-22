using System.Numerics;
using Xunit;

namespace CupriCurve.Tests;

/// <summary>Covers the public surface: small-order detection and the scalar helpers.</summary>
public class PublicApiTests
{
    private static readonly BigInteger L =
        BigInteger.Pow(2, 252) + BigInteger.Parse("27742317777372353535851937790883648493");

    private static byte[] ValidPublicKey(int seedByte)
    {
        var seed = new byte[32];
        Array.Fill(seed, (byte)seedByte);
        var pub = new byte[32];
        Ed25519ExpandedKey.FromSeed(seed).GetPublicKey(pub);
        return pub;
    }

    [Theory]
    // identity (order 1) and (0, -1) (order 2) are small-order points.
    [InlineData("0100000000000000000000000000000000000000000000000000000000000000")]
    [InlineData("ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f")]
    public void IsSmallOrder_True_For_Torsion_Points(string hex)
    {
        Assert.True(Ed25519Point.IsSmallOrder(Convert.FromHexString(hex)));
    }

    [Fact]
    public void IsSmallOrder_False_For_Prime_Order_Keys()
    {
        for (int i = 1; i < 10; i++)
            Assert.False(Ed25519Point.IsSmallOrder(ValidPublicKey(i)));
    }

    [Fact]
    public void Clamp_Sets_Expected_Bits()
    {
        var s = new byte[32];
        Array.Fill(s, (byte)0xFF);
        Ed25519Scalar.Clamp(s);
        Assert.Equal(0, s[0] & 0x07);   // low 3 bits cleared
        Assert.Equal(0x40, s[31] & 0xC0); // bit 255 clear, bit 254 set
    }

    [Fact]
    public void IsCanonical_Boundaries()
    {
        var zero = new byte[32];
        Assert.True(Ed25519Scalar.IsCanonical(zero));

        var lMinus1 = new byte[32];
        (L - 1).TryWriteBytes(lMinus1, out _, isUnsigned: true, isBigEndian: false);
        Assert.True(Ed25519Scalar.IsCanonical(lMinus1));

        var lBytes = new byte[32];
        L.TryWriteBytes(lBytes, out _, isUnsigned: true, isBigEndian: false);
        Assert.False(Ed25519Scalar.IsCanonical(lBytes));
    }

    [Fact]
    public void Reduce_And_MulAdd_Wrappers_Work()
    {
        // Reduce(L) == 0
        var wide = new byte[64];
        L.TryWriteBytes(wide, out _, isUnsigned: true, isBigEndian: false);
        var r = new byte[32];
        Ed25519Scalar.Reduce(wide, r);
        Assert.All(r, b => Assert.Equal(0, b));

        // MulAdd(2,3,4) == 10
        var a = new byte[32]; a[0] = 2;
        var b = new byte[32]; b[0] = 3;
        var c = new byte[32]; c[0] = 4;
        var outb = new byte[32];
        Ed25519Scalar.MulAdd(a, b, c, outb);
        Assert.Equal(10, outb[0]);
        Assert.All(outb.AsSpan(1).ToArray(), x => Assert.Equal(0, x));
    }
}
