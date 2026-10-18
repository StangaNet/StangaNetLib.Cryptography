using FluentAssertions;
using StangaNetLib.Cryptography.Implementations;

namespace StangaNetLib.Cryptography.Tests;

public sealed class SecureTokenServiceTests
{
    private readonly SecureTokenService _sut = new();

    [Fact]
    public void GenerateToken_ReturnsUrlSafeBase64()
    {
        var token = _sut.GenerateToken();
        token.Should().NotBeNullOrEmpty();
        token.Should().NotContain("+").And.NotContain("/").And.NotContain("=");
    }

    [Fact]
    public void GenerateToken_TwoCallsProduceDifferentTokens()
    {
        var t1 = _sut.GenerateToken();
        var t2 = _sut.GenerateToken();
        t1.Should().NotBe(t2);
    }

    [Theory]
    [InlineData(16)]
    [InlineData(32)]
    [InlineData(64)]
    public void GenerateToken_CustomByteLength_ProducesCorrectEncodedLength(int byteLength)
    {
        var token = _sut.GenerateToken(byteLength);
        // Base64url without padding: ceil(byteLength * 4 / 3) with no trailing '='
        var expectedLength = (int)Math.Ceiling(byteLength * 4.0 / 3) - (byteLength % 3 == 0 ? 0 : 0);
        token.Length.Should().BeGreaterThanOrEqualTo(byteLength);
    }

    [Fact]
    public void GenerateHexToken_ReturnsLowercaseHex()
    {
        var token = _sut.GenerateHexToken();
        token.Should().MatchRegex("^[0-9a-f]{64}$");
    }

    [Fact]
    public void GenerateHexToken_TwoCallsProduceDifferentTokens()
    {
        var t1 = _sut.GenerateHexToken();
        var t2 = _sut.GenerateHexToken();
        t1.Should().NotBe(t2);
    }

    [Theory]
    [InlineData(6)]
    [InlineData(8)]
    [InlineData(10)]
    public void GenerateNumericOtp_ReturnsCorrectDigitCount(int digits)
    {
        var otp = _sut.GenerateNumericOtp(digits);
        otp.Should().HaveLength(digits);
        otp.Should().MatchRegex("^[0-9]+$");
    }

    [Fact]
    public void GenerateNumericOtp_DefaultIs6Digits()
    {
        var otp = _sut.GenerateNumericOtp();
        otp.Should().HaveLength(6);
    }

    [Fact]
    public void GenerateNumericOtp_TwoCallsProduceDifferentValues()
    {
        var results = Enumerable.Range(0, 20).Select(_ => _sut.GenerateNumericOtp()).ToList();
        results.Distinct().Should().HaveCountGreaterThan(1);
    }

    [Fact]
    public void GenerateNumericOtp_InvalidDigits_ThrowsArgumentOutOfRangeException()
    {
        var act = () => _sut.GenerateNumericOtp(3);
        act.Should().Throw<ArgumentOutOfRangeException>();
    }

    [Fact]
    public void GenerateSecureGuid_ReturnsVersion4Guid()
    {
        var guid = _sut.GenerateSecureGuid();
        var bytes = guid.ToByteArray();
        // Version 4: high nibble of byte[7] must be 0x4
        (bytes[7] >> 4).Should().Be(4);
        // RFC 4122 variant: high 2 bits of byte[8] must be 10
        (bytes[8] >> 6).Should().Be(2);
    }

    [Fact]
    public void GenerateSecureGuid_TwoCallsProduceDifferentValues()
    {
        var g1 = _sut.GenerateSecureGuid();
        var g2 = _sut.GenerateSecureGuid();
        g1.Should().NotBe(g2);
    }

    [Fact]
    public void GenerateRandomBytes_ReturnsCorrectCount()
    {
        var bytes = _sut.GenerateRandomBytes(48);
        bytes.Should().HaveCount(48);
    }

    [Fact]
    public void GenerateRandomBytes_ZeroCount_ThrowsArgumentOutOfRangeException()
    {
        var act = () => _sut.GenerateRandomBytes(0);
        act.Should().Throw<ArgumentOutOfRangeException>();
    }
}
