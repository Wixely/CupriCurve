using System.Buffers.Binary;

namespace CupriCurve.Internal;

/// <summary>
/// Field element in GF(2^255 - 19), stored as five 51-bit limbs (radix 2^51) in 64-bit words.
/// All arithmetic is constant-time (no secret-dependent branching or table indexing).
/// This is the standard "fe51" representation used by ref10 / donna-c64.
/// </summary>
internal readonly struct Fe
{
    // value = l0 + l1*2^51 + l2*2^102 + l3*2^153 + l4*2^204  (mod 2^255-19)
    private readonly ulong l0, l1, l2, l3, l4;

    private const ulong Mask51 = 0x0007FFFFFFFFFFFFUL; // 2^51 - 1
    // Limbs of 2p = 2^256 - 38, used so subtraction never underflows.
    private const ulong TwoP0 = 0x000FFFFFFFFFFFDAUL; // 2^52 - 38
    private const ulong TwoP1234 = 0x000FFFFFFFFFFFFEUL; // 2^52 - 2

    internal Fe(ulong a0, ulong a1, ulong a2, ulong a3, ulong a4)
    {
        l0 = a0; l1 = a1; l2 = a2; l3 = a3; l4 = a4;
    }

    internal static readonly Fe Zero = new(0, 0, 0, 0, 0);
    internal static readonly Fe One = new(1, 0, 0, 0, 0);

    internal static Fe FromU64(ulong v) => new(v & Mask51, v >> 51, 0, 0, 0);

    private static ulong Load8(ReadOnlySpan<byte> b, int off) =>
        BinaryPrimitives.ReadUInt64LittleEndian(b.Slice(off));

    /// <summary>Load a field element from 32 little-endian bytes. Bit 255 is ignored.</summary>
    internal static Fe FromBytes(ReadOnlySpan<byte> b)
    {
        ulong a0 = Load8(b, 0) & Mask51;
        ulong a1 = (Load8(b, 6) >> 3) & Mask51;
        ulong a2 = (Load8(b, 12) >> 6) & Mask51;
        ulong a3 = (Load8(b, 19) >> 1) & Mask51;
        ulong a4 = (Load8(b, 24) >> 12) & Mask51;
        return new Fe(a0, a1, a2, a3, a4);
    }

    /// <summary>Serialize to 32 little-endian bytes, fully reduced (canonical) in constant time.</summary>
    internal void ToBytes(Span<byte> outb)
    {
        ulong h0 = l0, h1 = l1, h2 = l2, h3 = l3, h4 = l4;
        ulong c;
        c = h0 >> 51; h0 &= Mask51; h1 += c;
        c = h1 >> 51; h1 &= Mask51; h2 += c;
        c = h2 >> 51; h2 &= Mask51; h3 += c;
        c = h3 >> 51; h3 &= Mask51; h4 += c;
        c = h4 >> 51; h4 &= Mask51; h0 += 19 * c;
        c = h0 >> 51; h0 &= Mask51; h1 += c;

        // Conditionally subtract p (q == 1 iff h >= p).
        ulong q = (h0 + 19) >> 51;
        q = (h1 + q) >> 51;
        q = (h2 + q) >> 51;
        q = (h3 + q) >> 51;
        q = (h4 + q) >> 51;
        h0 += 19 * q;
        c = h0 >> 51; h0 &= Mask51; h1 += c;
        c = h1 >> 51; h1 &= Mask51; h2 += c;
        c = h2 >> 51; h2 &= Mask51; h3 += c;
        c = h3 >> 51; h3 &= Mask51; h4 += c;
        h4 &= Mask51;

        ulong b0 = h0 | (h1 << 51);
        ulong b1 = (h1 >> 13) | (h2 << 38);
        ulong b2 = (h2 >> 26) | (h3 << 25);
        ulong b3 = (h3 >> 39) | (h4 << 12);
        BinaryPrimitives.WriteUInt64LittleEndian(outb.Slice(0), b0);
        BinaryPrimitives.WriteUInt64LittleEndian(outb.Slice(8), b1);
        BinaryPrimitives.WriteUInt64LittleEndian(outb.Slice(16), b2);
        BinaryPrimitives.WriteUInt64LittleEndian(outb.Slice(24), b3);
    }

    internal static Fe Add(in Fe f, in Fe g) =>
        new(f.l0 + g.l0, f.l1 + g.l1, f.l2 + g.l2, f.l3 + g.l3, f.l4 + g.l4);

    internal static Fe Sub(in Fe f, in Fe g) =>
        new(f.l0 + TwoP0 - g.l0,
            f.l1 + TwoP1234 - g.l1,
            f.l2 + TwoP1234 - g.l2,
            f.l3 + TwoP1234 - g.l3,
            f.l4 + TwoP1234 - g.l4);

    internal static Fe Neg(in Fe f) => Sub(Zero, f);

    internal static Fe Mul(in Fe f, in Fe g)
    {
        ulong f0 = f.l0, f1 = f.l1, f2 = f.l2, f3 = f.l3, f4 = f.l4;
        ulong g0 = g.l0, g1 = g.l1, g2 = g.l2, g3 = g.l3, g4 = g.l4;
        ulong g1_19 = 19 * g1, g2_19 = 19 * g2, g3_19 = 19 * g3, g4_19 = 19 * g4;

        UInt128 r0 = (UInt128)f0 * g0 + (UInt128)f1 * g4_19 + (UInt128)f2 * g3_19 + (UInt128)f3 * g2_19 + (UInt128)f4 * g1_19;
        UInt128 r1 = (UInt128)f0 * g1 + (UInt128)f1 * g0 + (UInt128)f2 * g4_19 + (UInt128)f3 * g3_19 + (UInt128)f4 * g2_19;
        UInt128 r2 = (UInt128)f0 * g2 + (UInt128)f1 * g1 + (UInt128)f2 * g0 + (UInt128)f3 * g4_19 + (UInt128)f4 * g3_19;
        UInt128 r3 = (UInt128)f0 * g3 + (UInt128)f1 * g2 + (UInt128)f2 * g1 + (UInt128)f3 * g0 + (UInt128)f4 * g4_19;
        UInt128 r4 = (UInt128)f0 * g4 + (UInt128)f1 * g3 + (UInt128)f2 * g2 + (UInt128)f3 * g1 + (UInt128)f4 * g0;

        ulong c;
        c = (ulong)(r0 >> 51); ulong h0 = (ulong)r0 & Mask51; r1 += c;
        c = (ulong)(r1 >> 51); ulong h1 = (ulong)r1 & Mask51; r2 += c;
        c = (ulong)(r2 >> 51); ulong h2 = (ulong)r2 & Mask51; r3 += c;
        c = (ulong)(r3 >> 51); ulong h3 = (ulong)r3 & Mask51; r4 += c;
        c = (ulong)(r4 >> 51); ulong h4 = (ulong)r4 & Mask51; h0 += 19 * c;
        c = h0 >> 51; h0 &= Mask51; h1 += c;
        return new Fe(h0, h1, h2, h3, h4);
    }

    internal static Fe Sq(in Fe f) => Mul(f, f);

    private static Fe SqN(in Fe f, int n)
    {
        Fe r = f;
        for (int i = 0; i < n; i++) r = Sq(r);
        return r;
    }

    /// <summary>Modular inverse: f^(p-2). Constant-time (fixed addition chain, public exponent).</summary>
    internal static Fe Invert(in Fe z)
    {
        Fe t0 = Sq(z);
        Fe t1 = SqN(t0, 2);
        t1 = Mul(z, t1);
        t0 = Mul(t0, t1);
        Fe t2 = Sq(t0);
        t1 = Mul(t1, t2);
        t2 = SqN(t1, 5);
        t1 = Mul(t2, t1);
        t2 = SqN(t1, 10);
        t2 = Mul(t2, t1);
        Fe t3 = SqN(t2, 20);
        t2 = Mul(t3, t2);
        t2 = SqN(t2, 10);
        t1 = Mul(t2, t1);
        t2 = SqN(t1, 50);
        t2 = Mul(t2, t1);
        t3 = SqN(t2, 100);
        t2 = Mul(t3, t2);
        t2 = SqN(t2, 50);
        t1 = Mul(t2, t1);
        t1 = SqN(t1, 5);
        return Mul(t1, t0);
    }

    /// <summary>f^((p-5)/8), used for square roots during point decompression.</summary>
    internal static Fe Pow22523(in Fe z)
    {
        Fe t0 = Sq(z);
        Fe t1 = SqN(t0, 2);
        t1 = Mul(z, t1);
        t0 = Mul(t0, t1);
        t0 = Sq(t0);
        t0 = Mul(t1, t0);
        t1 = SqN(t0, 5);
        t0 = Mul(t1, t0);
        t1 = SqN(t0, 10);
        t1 = Mul(t1, t0);
        Fe t2 = SqN(t1, 20);
        t1 = Mul(t2, t1);
        t1 = SqN(t1, 10);
        t0 = Mul(t1, t0);
        t1 = SqN(t0, 50);
        t1 = Mul(t1, t0);
        t2 = SqN(t1, 100);
        t1 = Mul(t2, t1);
        t1 = SqN(t1, 50);
        t0 = Mul(t1, t0);
        t0 = SqN(t0, 2);
        return Mul(t0, z);
    }

    /// <summary>Exponentiation by a public little-endian exponent (used only for constants). Not constant-time in the exponent.</summary>
    internal static Fe Pow(in Fe b, ReadOnlySpan<byte> expLe)
    {
        Fe r = One;
        for (int i = 255; i >= 0; i--)
        {
            r = Sq(r);
            int bit = (expLe[i >> 3] >> (i & 7)) & 1;
            if (bit == 1) r = Mul(r, b);
        }
        return r;
    }

    internal static Fe CMov(in Fe a, in Fe b, int bit)
    {
        ulong m = (ulong)(-(long)bit); // 0x0 if bit==0, all-ones if bit==1
        return new Fe(
            a.l0 ^ (m & (a.l0 ^ b.l0)),
            a.l1 ^ (m & (a.l1 ^ b.l1)),
            a.l2 ^ (m & (a.l2 ^ b.l2)),
            a.l3 ^ (m & (a.l3 ^ b.l3)),
            a.l4 ^ (m & (a.l4 ^ b.l4)));
    }

    /// <summary>Least-significant bit of the canonical encoding (the Ed25519 "sign" of x).</summary>
    internal int IsNegative()
    {
        Span<byte> tmp = stackalloc byte[32];
        ToBytes(tmp);
        return tmp[0] & 1;
    }

    internal bool IsZero()
    {
        Span<byte> tmp = stackalloc byte[32];
        ToBytes(tmp);
        int acc = 0;
        for (int i = 0; i < 32; i++) acc |= tmp[i];
        return acc == 0;
    }

    internal static bool Equal(in Fe a, in Fe b)
    {
        Span<byte> x = stackalloc byte[32];
        Span<byte> y = stackalloc byte[32];
        a.ToBytes(x);
        b.ToBytes(y);
        int acc = 0;
        for (int i = 0; i < 32; i++) acc |= x[i] ^ y[i];
        return acc == 0;
    }
}
