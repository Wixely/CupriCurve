using System.Numerics;
using System.Text;
using Xunit;
using BcEd25519 = Org.BouncyCastle.Math.EC.Rfc8032.Ed25519;

namespace CupriCurve.Tests;

/// <summary>
/// End-to-end validation of Tor-style key blinding without external KATs:
///  - algebraic consistency: [a']B == A' == [h]A, and
///  - a signature made with the blinded expanded key verifies under the blinded public key (BouncyCastle).
/// This pins the exact behaviour a constant-time scalar rewrite must preserve.
/// </summary>
public class BlindingTests
{
    private static readonly BigInteger L =
        BigInteger.Pow(2, 252) + BigInteger.Parse("27742317777372353535851937790883648493");

    private static byte[] RandomBlindingScalar(Random rng)
    {
        // A reduced scalar in [0, L), as CupriTor would supply after deriving+clamping.
        Span<byte> wide = stackalloc byte[64];
        rng.NextBytes(wide);
        BigInteger v = new BigInteger(wide, isUnsigned: true, isBigEndian: false) % L;
        var outb = new byte[32];
        v.TryWriteBytes(outb, out _, isUnsigned: true, isBigEndian: false);
        return outb;
    }

    [Fact]
    public void BlindedScalarAndPublicKey_Are_Consistent()
    {
        var rng = new Random(20);
        var personalization = Encoding.ASCII.GetBytes("Derive temporary signing key hash input");

        for (int i = 0; i < 100; i++)
        {
            var seed = new byte[32];
            rng.NextBytes(seed);
            var key = Ed25519ExpandedKey.FromSeed(seed);
            var pub = new byte[32];
            key.GetPublicKey(pub);

            byte[] h = RandomBlindingScalar(rng);

            // A' via public-key blinding: [h]A
            var blindedPubFromPoint = new byte[32];
            Assert.True(TorBlinding.TryBlindPublicKey(pub, h, blindedPubFromPoint));

            // a' via private-key blinding, then [a']B
            var aPrime = new byte[32];
            var rhPrime = new byte[32];
            TorBlinding.BlindPrivateKey(key, h, personalization, aPrime, rhPrime);
            var blindedPubFromScalar = new byte[32];
            Ed25519Point.ScalarMultBase(aPrime, blindedPubFromScalar);

            Assert.Equal(blindedPubFromPoint, blindedPubFromScalar);
        }
    }

    [Fact]
    public void BlindedKey_Signs_Verifiably_Under_BlindedPublicKey()
    {
        var rng = new Random(21);
        var personalization = Encoding.ASCII.GetBytes("Derive temporary signing key hash input");

        for (int i = 0; i < 100; i++)
        {
            var seed = new byte[32];
            rng.NextBytes(seed);
            var key = Ed25519ExpandedKey.FromSeed(seed);

            byte[] h = RandomBlindingScalar(rng);

            var aPrime = new byte[32];
            var rhPrime = new byte[32];
            TorBlinding.BlindPrivateKey(key, h, personalization, aPrime, rhPrime);

            var blindedPub = new byte[32];
            Ed25519Point.ScalarMultBase(aPrime, blindedPub);

            var blindedKey = Ed25519ExpandedKey.FromParts(aPrime, rhPrime);
            var msg = new byte[rng.Next(0, 48)];
            rng.NextBytes(msg);

            var sig = new byte[64];
            Ed25519.SignWithExpandedKey(blindedKey, blindedPub, msg, sig);

            Assert.True(BcEd25519.Verify(sig, 0, blindedPub, 0, msg, 0, msg.Length),
                $"blinded signature #{i} failed to verify");
        }
    }
}
