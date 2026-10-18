using System.Security.Cryptography;
using System.Text;
using FluentAssertions;
using StangaNetLib.Cryptography.Implementations;
using StangaNetLib.Cryptography.Models;

namespace StangaNetLib.Cryptography.Tests;

public sealed class HmacServiceTests
{
    private readonly HmacService _sut = new();

    [Fact]
    public void Sign_Bytes_ReturnsSuccessWithHexSignature()
    {
        var data = "payload"u8.ToArray();
        var key = "secret"u8.ToArray();

        var result = _sut.Sign(data, key);

        result.IsSuccess.Should().BeTrue();
        result.Value.Should().MatchRegex("^[0-9a-f]{64}$");
    }

    [Fact]
    public void Sign_String_ReturnsSuccessWithHexSignature()
    {
        var result = _sut.Sign("payload", "secret");

        result.IsSuccess.Should().BeTrue();
        result.Value.Should().MatchRegex("^[0-9a-f]{64}$");
    }

    [Fact]
    public void Sign_SameInputProducesSameSignature()
    {
        var s1 = _sut.Sign("data", "key");
        var s2 = _sut.Sign("data", "key");
        s1.Value.Should().Be(s2.Value);
    }

    [Fact]
    public void Sign_DifferentKeysProduceDifferentSignatures()
    {
        var s1 = _sut.Sign("data", "key1");
        var s2 = _sut.Sign("data", "key2");
        s1.Value.Should().NotBe(s2.Value);
    }

    [Fact]
    public void Sign_EmptyKey_ReturnsValidationFailure()
    {
        var result = _sut.Sign("data"u8.ToArray(), Array.Empty<byte>());
        result.IsFailure.Should().BeTrue();
        result.Error.Code.Should().StartWith("Validation");
    }

    [Theory]
    [InlineData(CryptoHashAlgorithm.SHA256, 64)]
    [InlineData(CryptoHashAlgorithm.SHA384, 96)]
    [InlineData(CryptoHashAlgorithm.SHA512, 128)]
    public void Sign_AlgorithmProducesCorrectOutputLength(CryptoHashAlgorithm algorithm, int expectedHexLength)
    {
        var result = _sut.Sign("test", "key", algorithm);
        result.IsSuccess.Should().BeTrue();
        result.Value.Should().HaveLength(expectedHexLength);
    }

    [Theory]
    [InlineData(CryptoHashAlgorithm.SHA3_256, 64)]
    [InlineData(CryptoHashAlgorithm.SHA3_384, 96)]
    [InlineData(CryptoHashAlgorithm.SHA3_512, 128)]
    public void Sign_Sha3_ProducesCorrectLengthWhenSupported(CryptoHashAlgorithm algorithm, int expectedHexLength)
    {
        if (!HMACSHA3_256.IsSupported)
            return;

        var result = _sut.Sign("test", "key", algorithm);
        result.IsSuccess.Should().BeTrue();
        result.Value.Should().HaveLength(expectedHexLength);
    }

    [Fact]
    public void Verify_ReturnsTrueForValidSignature()
    {
        var data = "payload"u8.ToArray();
        var key = "secret"u8.ToArray();
        var sig = _sut.Sign(data, key).Value!;

        var result = _sut.Verify(data, sig, key);

        result.IsSuccess.Should().BeTrue();
        result.Value.Should().BeTrue();
    }

    [Fact]
    public void Verify_ReturnsFalseForTamperedData()
    {
        var key = "secret"u8.ToArray();
        var sig = _sut.Sign("original"u8.ToArray(), key).Value!;

        var result = _sut.Verify("tampered"u8.ToArray(), sig, key);

        result.IsSuccess.Should().BeTrue();
        result.Value.Should().BeFalse();
    }

    [Fact]
    public void Verify_String_ReturnsTrueForValidSignature()
    {
        var sig = _sut.Sign("hello", "mykey").Value!;
        var result = _sut.Verify("hello", sig, "mykey");
        result.Value.Should().BeTrue();
    }

    [Fact]
    public void Verify_EmptyKey_ReturnsValidationFailure()
    {
        var result = _sut.Verify("data"u8.ToArray(), "aabbcc", Array.Empty<byte>());
        result.IsFailure.Should().BeTrue();
    }
}
