using System.Numerics;
using Xunit;
using BcEd25519 = Org.BouncyCastle.Math.EC.Rfc8032.Ed25519;

namespace CupriCurve.Tests;

/// <summary>
/// <see cref="Ed25519.Verify"/> (RFC 8032): known-answer vectors cross-checked against BouncyCastle as an
/// independent oracle, sign/verify round-trips in both directions (including long messages), and the
/// negative / malleability / no-throw cases. BouncyCastle is the same trusted oracle the group tests use.
/// </summary>
public class SignVerifyTests
{
    private static readonly BigInteger L =
        BigInteger.Pow(2, 252) + BigInteger.Parse("27742317777372353535851937790883648493");

    // RFC 8032 §7.1 known-answer vectors (public key, message, signature). Each is asserted valid by BOTH our
    // Verify and BouncyCastle — so a mistyped constant fails the BC cross-check rather than masking a bug.
    public static IEnumerable<object[]> Rfc8032Vectors() => new[]
    {
        // TEST 1 (empty message)
        new object[]
        {
            "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a",
            "",
            "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b",
        },
        // TEST 2 (1-byte message)
        new object[]
        {
            "3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c",
            "72",
            "92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00",
        },
        // TEST 3 (2-byte message)
        new object[]
        {
            "fc51cd8e6218a1a38da47ed00230f0580816ed13ba3303ac5deb911548908025",
            "af82",
            "6291d657deec24024827e69c3abe01a30ce548a284743a445e3680d7db5ac3ac18ff9b538d16f290ae67f760984dc6594a7c15e9716ed28dc027beceea1ec40a",
        },
    };

    [Theory]
    [MemberData(nameof(Rfc8032Vectors))]
    public void Rfc8032_KnownAnswer_Vectors_Verify(string pkHex, string msgHex, string sigHex)
    {
        byte[] pk = Convert.FromHexString(pkHex);
        byte[] msg = Convert.FromHexString(msgHex);
        byte[] sig = Convert.FromHexString(sigHex);

        Assert.True(Ed25519.Verify(pk, msg, sig));
        // Independent cross-check: the same vector must also satisfy BouncyCastle (guards a wrong constant).
        Assert.True(BcEd25519.Verify(sig, 0, pk, 0, msg, 0, msg.Length));
    }

    [Fact]
    public void RoundTrips_With_Our_Own_Signer_Over_Many_Messages()
    {
        var rng = new Random(100);
        for (int i = 0; i < 200; i++)
        {
            byte[] seed = new byte[32]; rng.NextBytes(seed);
            var key = Ed25519ExpandedKey.FromSeed(seed);
            byte[] pub = new byte[32]; key.GetPublicKey(pub);

            byte[] msg = new byte[i == 0 ? 0 : rng.Next(0, 1200)]; // include the empty and >1KB messages
            rng.NextBytes(msg);

            byte[] sig = new byte[64];
            Ed25519.SignWithExpandedKey(key, pub, msg, sig);

            Assert.True(Ed25519.Verify(pub, msg, sig), $"round-trip #{i} (len {msg.Length}) failed");
        }
    }

    [Fact]
    public void Cross_Verifies_With_BouncyCastle_Both_Directions_Including_Long_Messages()
    {
        var rng = new Random(101);
        for (int i = 0; i < 100; i++)
        {
            byte[] seed = new byte[32]; rng.NextBytes(seed);

            byte[] pub = new byte[32];
            BcEd25519.GeneratePublicKey(seed, 0, pub, 0);

            // Cover exactly-1023 and larger messages (the RFC's long-vector regime) plus random lengths.
            int len = i switch { 0 => 0, 1 => 1023, 2 => 2048, _ => rng.Next(0, 1500) };
            byte[] msg = new byte[len]; rng.NextBytes(msg);

            // BC signs -> we verify.
            byte[] bcSig = new byte[64];
            BcEd25519.Sign(seed, 0, msg, 0, msg.Length, bcSig, 0);
            Assert.True(Ed25519.Verify(pub, msg, bcSig), $"BC signature #{i} (len {len}) rejected by our Verify");

            // We sign (from seed) -> BC verifies.
            byte[] ourSig = new byte[64];
            Ed25519.SignWithSeed(seed, msg, ourSig);
            Assert.True(BcEd25519.Verify(ourSig, 0, pub, 0, msg, 0, msg.Length), $"our signature #{i} (len {len}) rejected by BC");

            // Ed25519 is deterministic, so the two signatures must be byte-identical.
            Assert.Equal(bcSig, ourSig);
        }
    }

    [Fact]
    public void PublicKeyFromSeed_Matches_The_Expanded_Key_Derivation()
    {
        var rng = new Random(106);
        for (int i = 0; i < 50; i++)
        {
            byte[] seed = new byte[32]; rng.NextBytes(seed);
            byte[] viaWrapper = new byte[32]; Ed25519.PublicKeyFromSeed(seed, viaWrapper);
            byte[] viaKey = new byte[32]; Ed25519ExpandedKey.FromSeed(seed).GetPublicKey(viaKey);
            Assert.Equal(viaKey, viaWrapper);
        }
    }

    [Fact]
    public void Rejects_Tampered_Message_R_S_And_Wrong_Key()
    {
        byte[] seed = new byte[32]; new Random(102).NextBytes(seed);
        var key = Ed25519ExpandedKey.FromSeed(seed);
        byte[] pub = new byte[32]; key.GetPublicKey(pub);
        byte[] msg = Convert.FromHexString("00112233445566778899aabbccddeeff");
        byte[] sig = new byte[64];
        Ed25519.SignWithExpandedKey(key, pub, msg, sig);
        Assert.True(Ed25519.Verify(pub, msg, sig)); // sanity: the untampered signature verifies

        byte[] badMsg = (byte[])msg.Clone(); badMsg[3] ^= 0x01;
        Assert.False(Ed25519.Verify(pub, badMsg, sig));

        byte[] badR = (byte[])sig.Clone(); badR[5] ^= 0x01;   // flip a bit in R (first half)
        Assert.False(Ed25519.Verify(pub, msg, badR));

        byte[] badS = (byte[])sig.Clone(); badS[40] ^= 0x01;  // flip a bit in S (second half)
        Assert.False(Ed25519.Verify(pub, msg, badS));

        byte[] otherSeed = new byte[32]; Array.Fill(otherSeed, (byte)9);
        byte[] otherPub = new byte[32]; Ed25519.PublicKeyFromSeed(otherSeed, otherPub);
        Assert.False(Ed25519.Verify(otherPub, msg, sig));
    }

    [Fact]
    public void Rejects_Non_Canonical_S_Malleability()
    {
        byte[] seed = new byte[32]; new Random(103).NextBytes(seed);
        var key = Ed25519ExpandedKey.FromSeed(seed);
        byte[] pub = new byte[32]; key.GetPublicKey(pub);
        byte[] msg = Convert.FromHexString("deadbeef");
        byte[] sig = new byte[64];
        Ed25519.SignWithExpandedKey(key, pub, msg, sig);
        Assert.True(Ed25519.Verify(pub, msg, sig));

        // S' = S + L is congruent mod L ([S']B == [S]B) but non-canonical; a strict verifier must reject it.
        var s = new BigInteger(sig.AsSpan(32, 32).ToArray(), isUnsigned: true, isBigEndian: false);
        byte[] malleable = (byte[])sig.Clone();
        byte[] sBytes = new byte[32];
        (s + L).TryWriteBytes(sBytes, out _, isUnsigned: true, isBigEndian: false);
        sBytes.CopyTo(malleable.AsSpan(32));

        Assert.False(Ed25519.Verify(pub, msg, malleable));
        Assert.False(BcEd25519.Verify(malleable, 0, pub, 0, msg, 0, msg.Length)); // BC agrees it's invalid
    }

    [Fact]
    public void Rejects_Wrong_Lengths_And_Never_Throws()
    {
        byte[] seed = new byte[32]; new Random(104).NextBytes(seed);
        var key = Ed25519ExpandedKey.FromSeed(seed);
        byte[] pub = new byte[32]; key.GetPublicKey(pub);
        byte[] msg = Convert.FromHexString("abcdef");
        byte[] sig = new byte[64];
        Ed25519.SignWithExpandedKey(key, pub, msg, sig);

        Assert.False(Ed25519.Verify(new byte[31], msg, sig));            // pubkey too short
        Assert.False(Ed25519.Verify(new byte[33], msg, sig));            // pubkey too long
        Assert.False(Ed25519.Verify(pub, msg, new byte[63]));            // signature too short
        Assert.False(Ed25519.Verify(pub, msg, new byte[65]));            // signature too long
        Assert.False(Ed25519.Verify(ReadOnlySpan<byte>.Empty, msg, sig));
        Assert.False(Ed25519.Verify(pub, msg, ReadOnlySpan<byte>.Empty));

        // All-zero and random garbage must fail closed, not throw.
        Assert.False(Ed25519.Verify(new byte[32], msg, new byte[64]));
        byte[] garbage = new byte[64]; new Random(105).NextBytes(garbage);
        Assert.False(Ed25519.Verify(new byte[32], msg, garbage));
    }

    [Theory]
    // Identity (order 1) and (0, -1) (order 2) are small-order points and must be rejected as public keys.
    [InlineData("0100000000000000000000000000000000000000000000000000000000000000")]
    [InlineData("ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f")]
    public void Rejects_Small_Order_Public_Key(string pkHex)
    {
        byte[] pk = Convert.FromHexString(pkHex);
        byte[] msg = Convert.FromHexString("00");
        byte[] sig = new byte[64]; // S = 0 is canonical, so the small-order key is what forces rejection
        Assert.False(Ed25519.Verify(pk, msg, sig));
    }
}
