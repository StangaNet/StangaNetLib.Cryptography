using System.Security.Cryptography;
using FluentAssertions;
using StangaNetLib.Cryptography.Implementations;
using StangaNetLib.Cryptography.Models;

namespace StangaNetLib.Cryptography.Tests;

public sealed class HashServiceTests
{
    private readonly HashService _sut = new();

    [Fact]
    public void ComputeHash_Bytes_ReturnsLowercaseHex()
    {
        var data = "hello"u8.ToArray();
        var hash = _sut.ComputeHash(data);
        hash.Should().MatchRegex("^[0-9a-f]{64}$");
    }

    [Fact]
    public void ComputeHash_String_ReturnsLowercaseHex()
    {
        var hash = _sut.ComputeHash("hello");
        hash.Should().MatchRegex("^[0-9a-f]{64}$");
    }

    [Fact]
    public void ComputeHash_SameInputProducesSameOutput()
    {
        var h1 = _sut.ComputeHash("deterministic");
        var h2 = _sut.ComputeHash("deterministic");
        h1.Should().Be(h2);
    }

    [Fact]
    public void ComputeHash_DifferentInputsProduceDifferentHashes()
    {
        var h1 = _sut.ComputeHash("hello");
        var h2 = _sut.ComputeHash("world");
        h1.Should().NotBe(h2);
    }

    [Theory]
    [InlineData(CryptoHashAlgorithm.SHA256, 64)]
    [InlineData(CryptoHashAlgorithm.SHA384, 96)]
    [InlineData(CryptoHashAlgorithm.SHA512, 128)]
    public void ComputeHash_AlgorithmProducesCorrectOutputLength(CryptoHashAlgorithm algorithm, int expectedHexLength)
    {
        var hash = _sut.ComputeHash("test", algorithm);
        hash.Should().HaveLength(expectedHexLength);
    }

    [Theory]
    [InlineData(CryptoHashAlgorithm.SHA3_256, 64)]
    [InlineData(CryptoHashAlgorithm.SHA3_384, 96)]
    [InlineData(CryptoHashAlgorithm.SHA3_512, 128)]
    public void ComputeHash_Sha3_ProducesCorrectLengthWhenSupported(CryptoHashAlgorithm algorithm, int expectedHexLength)
    {
        if (!SHA3_256.IsSupported)
            return;

        var hash = _sut.ComputeHash("test", algorithm);
        hash.Should().HaveLength(expectedHexLength);
    }

    [Fact]
    public void ComputeHashBase64_Bytes_ReturnsValidBase64()
    {
        var data = "hello"u8.ToArray();
        var hash = _sut.ComputeHashBase64(data);

        var bytes = Convert.FromBase64String(hash); // must not throw
        bytes.Should().HaveCount(32); // SHA-256 = 32 bytes
    }

    [Fact]
    public void ComputeHashBase64_String_ReturnsSameAsBytes()
    {
        var input = "hello";
        var fromString = _sut.ComputeHashBase64(input);
        var fromBytes = _sut.ComputeHashBase64(System.Text.Encoding.UTF8.GetBytes(input));
        fromString.Should().Be(fromBytes);
    }

    [Fact]
    public void VerifyHash_ReturnsTrueForMatchingHash()
    {
        var data = "hello"u8.ToArray();
        var hash = _sut.ComputeHash(data);
        _sut.VerifyHash(data, hash).Should().BeTrue();
    }

    [Fact]
    public void VerifyHash_ReturnsFalseForTamperedData()
    {
        var hash = _sut.ComputeHash("hello");
        _sut.VerifyHash("world", hash).Should().BeFalse();
    }

    [Fact]
    public void VerifyHash_IsCaseInsensitiveForExpectedHash()
    {
        var data = "hello"u8.ToArray();
        var hash = _sut.ComputeHash(data).ToUpperInvariant();
        _sut.VerifyHash(data, hash).Should().BeTrue();
    }

    [Fact]
    public void VerifyHashBase64_ReturnsTrueForMatchingHash()
    {
        var data = "hello"u8.ToArray();
        var hash = _sut.ComputeHashBase64(data);
        _sut.VerifyHashBase64(data, hash).Should().BeTrue();
    }

    [Fact]
    public void VerifyHashBase64_ReturnsFalseForTamperedData()
    {
        var hash = _sut.ComputeHashBase64("hello"u8.ToArray());
        _sut.VerifyHashBase64("world"u8.ToArray(), hash).Should().BeFalse();
    }

    [Fact]
    public void VerifyHashBase64_String_RoundTrip()
    {
        var hash = _sut.ComputeHashBase64("hello");
        _sut.VerifyHashBase64("hello", hash).Should().BeTrue();
    }

    [Fact]
    public void ComputeHash_NullBytes_ThrowsArgumentNullException()
    {
        var act = () => _sut.ComputeHash((byte[])null!);
        act.Should().Throw<ArgumentNullException>();
    }

    [Fact]
    public void ComputeHash_EmptyString_ThrowsArgumentException()
    {
        var act = () => _sut.ComputeHash(string.Empty);
        act.Should().Throw<ArgumentException>();
    }
}
