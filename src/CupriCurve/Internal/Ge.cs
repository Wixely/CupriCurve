namespace CupriCurve.Internal;

/// <summary>
/// Point on the Ed25519 twisted-Edwards curve in extended homogeneous coordinates (X:Y:Z:T),
/// with x = X/Z, y = Y/Z, x*y = T/Z. Addition and doubling use the complete "hwcd" formulas
/// (valid for all inputs since a = -1 and d is a non-square), so scalar multiplication is
/// branch-free and constant-time.
/// </summary>
internal readonly struct Ge
{
    internal readonly Fe X, Y, Z, T;

    internal Ge(in Fe x, in Fe y, in Fe z, in Fe t) { X = x; Y = y; Z = z; T = t; }

    // Curve constants, derived at load time (no hard-coded big literals).
    internal static readonly Fe D;      // -121665/121666
    internal static readonly Fe D2;     // 2*d
    internal static readonly Fe SqrtM1; // sqrt(-1) = 2^((p-1)/4)
    internal static readonly Ge B;      // base point
    internal static readonly Ge Identity = new(Fe.Zero, Fe.One, Fe.One, Fe.Zero);

    static Ge()
    {
        D = Fe.Mul(Fe.Neg(Fe.FromU64(121665)), Fe.Invert(Fe.FromU64(121666)));
        D2 = Fe.Add(D, D);

        // (p-1)/4 = 2^253 - 5, little-endian.
        Span<byte> exp = stackalloc byte[32];
        exp.Fill(0xFF);
        exp[0] = 0xFB;
        exp[31] = 0x1F;
        SqrtM1 = Fe.Pow(Fe.FromU64(2), exp);

        Fe by = Fe.Mul(Fe.FromU64(4), Fe.Invert(Fe.FromU64(5)));
        if (!RecoverX(by, 0, out Fe bx))
            throw new InvalidOperationException("Ed25519 base point recovery failed (internal error).");
        B = new Ge(bx, by, Fe.One, Fe.Mul(bx, by));
    }

    internal static Ge Add(in Ge p, in Ge q)
    {
        Fe a = Fe.Mul(Fe.Sub(p.Y, p.X), Fe.Sub(q.Y, q.X));
        Fe b = Fe.Mul(Fe.Add(p.Y, p.X), Fe.Add(q.Y, q.X));
        Fe c = Fe.Mul(Fe.Mul(p.T, D2), q.T);
        Fe d = Fe.Add(Fe.Mul(p.Z, q.Z), Fe.Mul(p.Z, q.Z));
        Fe e = Fe.Sub(b, a);
        Fe f = Fe.Sub(d, c);
        Fe g = Fe.Add(d, c);
        Fe h = Fe.Add(b, a);
        // X3 = E*F, Y3 = G*H, Z3 = F*G, T3 = E*H
        return new Ge(Fe.Mul(e, f), Fe.Mul(g, h), Fe.Mul(f, g), Fe.Mul(e, h));
    }

    internal static Ge Double(in Ge p)
    {
        Fe a = Fe.Sq(p.X);
        Fe b = Fe.Sq(p.Y);
        Fe c = Fe.Add(Fe.Sq(p.Z), Fe.Sq(p.Z));
        Fe d = Fe.Neg(a); // a * X^2, a = -1
        Fe xy = Fe.Add(p.X, p.Y);
        Fe e = Fe.Sub(Fe.Sub(Fe.Sq(xy), a), b);
        Fe g = Fe.Add(d, b);
        Fe f = Fe.Sub(g, c);
        Fe h = Fe.Sub(d, b);
        // X3 = E*F, Y3 = G*H, Z3 = F*G, T3 = E*H
        return new Ge(Fe.Mul(e, f), Fe.Mul(g, h), Fe.Mul(f, g), Fe.Mul(e, h));
    }

    private static Ge CMov(in Ge a, in Ge b, int bit) =>
        new(Fe.CMov(a.X, b.X, bit), Fe.CMov(a.Y, b.Y, bit), Fe.CMov(a.Z, b.Z, bit), Fe.CMov(a.T, b.T, bit));

    /// <summary>Constant-time scalar multiplication [s]P for a little-endian 256-bit scalar.</summary>
    internal static Ge ScalarMult(ReadOnlySpan<byte> s, in Ge p)
    {
        Ge r = Identity;
        for (int i = 255; i >= 0; i--)
        {
            r = Double(r);
            int bit = (s[i >> 3] >> (i & 7)) & 1;
            Ge t = Add(r, p);
            r = CMov(r, t, bit);
        }
        return r;
    }

    internal static Ge ScalarMultBase(ReadOnlySpan<byte> s) => ScalarMult(s, B);

    internal void ToBytes(Span<byte> outb)
    {
        Fe zinv = Fe.Invert(Z);
        Fe x = Fe.Mul(X, zinv);
        Fe y = Fe.Mul(Y, zinv);
        y.ToBytes(outb);
        outb[31] ^= (byte)(x.IsNegative() << 7);
    }

    internal bool IsIdentity() => X.IsZero() && Fe.Equal(Y, Z);

    /// <summary>Recover x from y and the desired sign bit. Returns false if no valid x exists.</summary>
    internal static bool RecoverX(in Fe y, int sign, out Fe x)
    {
        Fe y2 = Fe.Sq(y);
        Fe u = Fe.Sub(y2, Fe.One);
        Fe v = Fe.Add(Fe.Mul(D, y2), Fe.One);
        Fe v3 = Fe.Mul(Fe.Sq(v), v);
        Fe v7 = Fe.Mul(Fe.Sq(v3), v);
        x = Fe.Mul(Fe.Pow22523(Fe.Mul(u, v7)), Fe.Mul(v3, u));

        // The curve equation is v*x^2 == u. The candidate may be off by a factor of sqrt(-1)
        // (when the quartic residue is +/- i), so try that correction and re-check the invariant
        // directly rather than testing for the -u case.
        if (!Fe.Equal(Fe.Mul(v, Fe.Sq(x)), u))
        {
            x = Fe.Mul(x, SqrtM1);
            if (!Fe.Equal(Fe.Mul(v, Fe.Sq(x)), u))
            {
                x = Fe.Zero;
                return false;
            }
        }

        if (x.IsZero() && sign == 1)
            return false; // non-canonical negative zero
        if (x.IsNegative() != sign)
            x = Fe.Neg(x);
        return true;
    }

    /// <summary>Decode a 32-byte compressed point. Returns false for non-canonical or off-curve encodings.</summary>
    internal static bool TryDecode(ReadOnlySpan<byte> point, out Ge result)
    {
        result = Identity;

        // Reject non-canonical y (y >= p): re-encode and compare (ignoring the sign bit).
        Fe y = Fe.FromBytes(point);
        Span<byte> reencoded = stackalloc byte[32];
        y.ToBytes(reencoded);
        int diff = (reencoded[31] & 0x7F) ^ (point[31] & 0x7F);
        for (int i = 0; i < 31; i++) diff |= reencoded[i] ^ point[i];
        if (diff != 0)
            return false;

        int sign = point[31] >> 7;
        if (!RecoverX(y, sign, out Fe x))
            return false;

        result = new Ge(x, y, Fe.One, Fe.Mul(x, y));
        return true;
    }
}
