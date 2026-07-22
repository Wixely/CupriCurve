using System.Security.Cryptography;
using Xunit;
using BcEd25519 = Org.BouncyCastle.Math.EC.Rfc8032.Ed25519;

namespace CupriCurve.Tests;

/// <summary>
/// Validates group operations against BouncyCastle's RFC 8032 implementation as the trusted oracle:
/// public-key derivation, point encode/decode round-trips, and signing (verified by BouncyCastle).
/// </summary>
public class GroupTests
{
    private static byte[] RandomSeed(Random rng)
    {
        var s = new byte[32];
        rng.NextBytes(s);
        return s;
    }

    [Fact]
    public void PublicKey_Matches_BouncyCastle()
    {
        var rng = new Random(10);
        for (int i = 0; i < 200; i++)
        {
            byte[] seed = RandomSeed(rng);

            var mine = new byte[32];
            Ed25519ExpandedKey.FromSeed(seed).GetPublicKey(mine);

            var bc = new byte[32];
            BcEd25519.GeneratePublicKey(seed, 0, bc, 0);

            Assert.Equal(bc, mine);
        }
    }

    [Fact]
    public void Decode_Encode_RoundTrips()
    {
        var rng = new Random(11);
        for (int i = 0; i < 200; i++)
        {
            byte[] seed = RandomSeed(rng);
            var pub = new byte[32];
            BcEd25519.GeneratePublicKey(seed, 0, pub, 0);

            Assert.True(Ed25519Point.TryDecode(pub, out var handle));
            var outb = new byte[32];
            Ed25519Point.Encode(handle, outb);
            Assert.Equal(pub, outb);
        }
    }

    [Fact]
    public void Signature_Verifies_In_BouncyCastle()
    {
        var rng = new Random(12);
        for (int i = 0; i < 100; i++)
        {
            byte[] seed = RandomSeed(rng);
            var key = Ed25519ExpandedKey.FromSeed(seed);
            var pub = new byte[32];
            key.GetPublicKey(pub);

            var msg = new byte[rng.Next(0, 64)];
            rng.NextBytes(msg);

            var sig = new byte[64];
            Ed25519.SignWithExpandedKey(key, pub, msg, sig);

            bool ok = BcEd25519.Verify(sig, 0, pub, 0, msg, 0, msg.Length);
            Assert.True(ok, $"signature #{i} failed to verify");
        }
    }

    [Fact]
    public void ScalarMultBase_Equals_BouncyCastle_For_Clamped_Scalars()
    {
        var rng = new Random(13);
        for (int i = 0; i < 100; i++)
        {
            byte[] seed = RandomSeed(rng);
            // BouncyCastle public key is [clamp(H(seed)[0..32])]B; compare to our base mult on the same scalar.
            var h = SHA512.HashData(seed);
            var scalar = h.AsSpan(0, 32).ToArray();
            scalar[0] &= 248; scalar[31] &= 127; scalar[31] |= 64;

            var mine = new byte[32];
            Ed25519Point.ScalarMultBase(scalar, mine);

            var bc = new byte[32];
            BcEd25519.GeneratePublicKey(seed, 0, bc, 0);

            Assert.Equal(bc, mine);
        }
    }
}
