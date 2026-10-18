using FluentAssertions;
using StangaNetLib.Cryptography.Implementations;
using StangaNetLib.Cryptography.Models;

namespace StangaNetLib.Cryptography.Tests;

public sealed class RsaDigitalSignatureServiceTests
{
    private readonly RsaDigitalSignatureService _sut = new();

    [Fact]
    public void GenerateKeyPair_ReturnsSuccessWithPemStrings()
    {
        var result = _sut.GenerateKeyPair();

        result.IsSuccess.Should().BeTrue();
        result.Value!.PublicKeyPem.Should().StartWith("-----BEGIN PUBLIC KEY-----");
        result.Value.PrivateKeyPem.Should().StartWith("-----BEGIN PRIVATE KEY-----");
    }

    [Fact]
    public void GenerateKeyPair_4096_ReturnsSuccess()
    {
        var result = _sut.GenerateKeyPair(4096);
        result.IsSuccess.Should().BeTrue();
    }

    [Fact]
    public void GenerateKeyPair_KeySizeTooSmall_ReturnsValidationFailure()
    {
        var result = _sut.GenerateKeyPair(1024);
        result.IsFailure.Should().BeTrue();
        result.Error.Code.Should().StartWith("Validation");
    }

    [Fact]
    public void GenerateKeyPair_KeySizeNotMultipleOf64_ReturnsValidationFailure()
    {
        var result = _sut.GenerateKeyPair(2050);
        result.IsFailure.Should().BeTrue();
    }

    [Fact]
    public void Sign_AndVerify_Pss_RoundTrip()
    {
        var keyPair = _sut.GenerateKeyPair().Value!;
        var data = "important message"u8.ToArray();

        var signResult = _sut.Sign(data, keyPair.PrivateKeyPem);
        signResult.IsSuccess.Should().BeTrue();

        var verifyResult = _sut.Verify(data, signResult.Value!, keyPair.PublicKeyPem);
        verifyResult.IsSuccess.Should().BeTrue();
        verifyResult.Value.Should().BeTrue();
    }

    [Fact]
    public void Sign_AndVerify_Pkcs1_RoundTrip()
    {
        var keyPair = _sut.GenerateKeyPair().Value!;
        var data = "important message"u8.ToArray();

        var signResult = _sut.Sign(data, keyPair.PrivateKeyPem, usePss: false);
        signResult.IsSuccess.Should().BeTrue();

        var verifyResult = _sut.Verify(data, signResult.Value!, keyPair.PublicKeyPem, usePss: false);
        verifyResult.IsSuccess.Should().BeTrue();
        verifyResult.Value.Should().BeTrue();
    }

    [Fact]
    public void Verify_PaddingMismatch_PssSignatureWithPkcs1Verify_ReturnsFalse()
    {
        var kp = _sut.GenerateKeyPair().Value!;
        var data = "test"u8.ToArray();
        var pssSig = _sut.Sign(data, kp.PrivateKeyPem, usePss: true).Value!;

        var result = _sut.Verify(data, pssSig, kp.PublicKeyPem, usePss: false);

        result.IsSuccess.Should().BeTrue();
        result.Value.Should().BeFalse();
    }

    [Fact]
    public void Verify_TamperedData_ReturnsFalse()
    {
        var keyPair = _sut.GenerateKeyPair().Value!;
        var sig = _sut.Sign("original"u8.ToArray(), keyPair.PrivateKeyPem).Value!;

        var result = _sut.Verify("tampered"u8.ToArray(), sig, keyPair.PublicKeyPem);

        result.IsSuccess.Should().BeTrue();
        result.Value.Should().BeFalse();
    }

    [Fact]
    public void Verify_WrongPublicKey_ReturnsFalse()
    {
        var kp1 = _sut.GenerateKeyPair().Value!;
        var kp2 = _sut.GenerateKeyPair().Value!;
        var data = "test"u8.ToArray();
        var sig = _sut.Sign(data, kp1.PrivateKeyPem).Value!;

        var result = _sut.Verify(data, sig, kp2.PublicKeyPem);

        result.IsSuccess.Should().BeTrue();
        result.Value.Should().BeFalse();
    }

    [Fact]
    public void Verify_InvalidBase64Signature_ReturnsValidationFailure()
    {
        var kp = _sut.GenerateKeyPair().Value!;
        var result = _sut.Verify("data"u8.ToArray(), "not-valid-base64!!!", kp.PublicKeyPem);

        result.IsFailure.Should().BeTrue();
        result.Error.Code.Should().StartWith("Validation");
    }

    [Theory]
    [InlineData(CryptoHashAlgorithm.SHA256)]
    [InlineData(CryptoHashAlgorithm.SHA384)]
    [InlineData(CryptoHashAlgorithm.SHA512)]
    public void Sign_AndVerify_Pss_AllHashAlgorithms(CryptoHashAlgorithm algorithm)
    {
        var kp = _sut.GenerateKeyPair().Value!;
        var data = "test"u8.ToArray();

        var sig = _sut.Sign(data, kp.PrivateKeyPem, algorithm).Value!;
        var valid = _sut.Verify(data, sig, kp.PublicKeyPem, algorithm).Value;

        valid.Should().BeTrue();
    }
}
