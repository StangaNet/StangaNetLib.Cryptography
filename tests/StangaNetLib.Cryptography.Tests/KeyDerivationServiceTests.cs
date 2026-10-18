using FluentAssertions;
using Microsoft.Extensions.Options;
using StangaNetLib.Cryptography.Implementations;
using StangaNetLib.Cryptography.Settings;

namespace StangaNetLib.Cryptography.Tests;

public sealed class KeyDerivationServiceTests
{
    private static KeyDerivationService CreateSut(int iterations = 10_000) =>
        new(Options.Create(new CryptographySettings
        {
            Pbkdf2Iterations = iterations,
            DefaultSaltLengthBytes = 16,
            DefaultKeyLengthBytes = 32,
        }));

    [Fact]
    public void DeriveKeyPbkdf2_ReturnsSuccess()
    {
        var sut = CreateSut();
        var result = sut.DeriveKeyPbkdf2("password");

        result.IsSuccess.Should().BeTrue();
        result.Value!.Key.Should().HaveCount(32);
        result.Value.Salt.Should().HaveCount(16);
        result.Value.Algorithm.Should().Be("PBKDF2-SHA256");
    }

    [Fact]
    public void DeriveKeyPbkdf2_SamePasswordAndSaltProduceSameKey()
    {
        var sut = CreateSut();
        var salt = new byte[16];

        var r1 = sut.DeriveKeyPbkdf2("password", salt, 10_000, 32);
        var r2 = sut.DeriveKeyPbkdf2("password", salt, 10_000, 32);

        r1.Value!.Key.Should().Equal(r2.Value!.Key);
    }

    [Fact]
    public void DeriveKeyPbkdf2_DifferentSaltProducesDifferentKey()
    {
        var sut = CreateSut();
        var r1 = sut.DeriveKeyPbkdf2("password");
        var r2 = sut.DeriveKeyPbkdf2("password");

        r1.Value!.Key.Should().NotEqual(r2.Value!.Key);
    }

    [Fact]
    public void DeriveKeyPbkdf2_EmptyPassword_ReturnsValidationFailure()
    {
        var sut = CreateSut();
        var result = sut.DeriveKeyPbkdf2(string.Empty);

        result.IsFailure.Should().BeTrue();
        result.Error.Code.Should().StartWith("Validation");
    }

    [Fact]
    public void DeriveKeyPbkdf2_CustomKeyLength_ProducesCorrectLength()
    {
        var sut = CreateSut();
        var result = sut.DeriveKeyPbkdf2("password", keyLengthBytes: 64);

        result.Value!.Key.Should().HaveCount(64);
    }

    [Fact]
    public void DeriveKeyHkdf_ReturnsSuccessWithCorrectLength()
    {
        var sut = CreateSut();
        var ikm = new byte[32];
        var result = sut.DeriveKeyHkdf(ikm, outputLengthBytes: 48);

        result.IsSuccess.Should().BeTrue();
        result.Value!.Should().HaveCount(48);
    }

    [Fact]
    public void DeriveKeyHkdf_SameInputProducesSameOutput()
    {
        var sut = CreateSut();
        var ikm = new byte[] { 1, 2, 3, 4, 5 };
        var salt = new byte[] { 10, 20, 30 };
        var info = new byte[] { 0x01 };

        var k1 = sut.DeriveKeyHkdf(ikm, salt, info, 32);
        var k2 = sut.DeriveKeyHkdf(ikm, salt, info, 32);

        k1.Value!.Should().Equal(k2.Value!);
    }

    [Fact]
    public void DeriveKeyHkdf_EmptyIkm_ReturnsValidationFailure()
    {
        var sut = CreateSut();
        var result = sut.DeriveKeyHkdf(Array.Empty<byte>());

        result.IsFailure.Should().BeTrue();
        result.Error.Code.Should().StartWith("Validation");
    }

    [Fact]
    public void DeriveKeyHkdf_ZeroOutputLength_ReturnsValidationFailure()
    {
        var sut = CreateSut();
        var result = sut.DeriveKeyHkdf(new byte[16], outputLengthBytes: 0);

        result.IsFailure.Should().BeTrue();
        result.Error.Code.Should().StartWith("Validation");
    }

    [Fact]
    public void GenerateSalt_ReturnsCorrectLength()
    {
        var sut = CreateSut();
        var salt = sut.GenerateSalt(24);
        salt.Should().HaveCount(24);
    }

    [Fact]
    public void GenerateSalt_TwoCallsProduceDifferentValues()
    {
        var sut = CreateSut();
        var s1 = sut.GenerateSalt();
        var s2 = sut.GenerateSalt();
        s1.Should().NotEqual(s2);
    }
}
