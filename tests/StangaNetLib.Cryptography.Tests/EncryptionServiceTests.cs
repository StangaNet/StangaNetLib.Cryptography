using System.Text;
using FluentAssertions;
using StangaNetLib.Cryptography.Implementations;

namespace StangaNetLib.Cryptography.Tests;

public sealed class EncryptionServiceTests
{
    private readonly AesGcmEncryptionService _sut = new();

    private static byte[] Key128 => new byte[16];
    private static byte[] Key256 => new byte[32];

    [Fact]
    public void Encrypt_Bytes_ReturnsSuccess()
    {
        var result = _sut.Encrypt("hello"u8.ToArray(), Key256);
        result.IsSuccess.Should().BeTrue();
        result.Value!.Length.Should().BeGreaterThan(28); // nonce(12) + tag(16) + at least 1 byte
    }

    [Fact]
    public void Decrypt_AfterEncrypt_ReturnsOriginalPlaintext()
    {
        var plaintext = Encoding.UTF8.GetBytes("secret message");
        var encrypted = _sut.Encrypt(plaintext, Key256).Value!;

        var result = _sut.Decrypt(encrypted, Key256);

        result.IsSuccess.Should().BeTrue();
        result.Value!.Should().Equal(plaintext);
    }

    [Fact]
    public void Encrypt_EmptyPlaintext_ReturnsSuccessWithNonceAndTag()
    {
        var result = _sut.Encrypt(Array.Empty<byte>(), Key256);
        result.IsSuccess.Should().BeTrue();
        result.Value!.Should().HaveCount(28); // nonce(12) + tag(16)
    }

    [Fact]
    public void Encrypt_InvalidKeyLength_ReturnsValidationFailure()
    {
        var result = _sut.Encrypt("data"u8.ToArray(), new byte[15]);
        result.IsFailure.Should().BeTrue();
        result.Error.Code.Should().StartWith("Validation");
    }

    [Theory]
    [InlineData(16)]
    [InlineData(24)]
    [InlineData(32)]
    public void Encrypt_AllValidKeySizes_Succeeds(int keySize)
    {
        var key = new byte[keySize];
        var result = _sut.Encrypt("test"u8.ToArray(), key);
        result.IsSuccess.Should().BeTrue();
    }

    [Fact]
    public void Decrypt_TamperedCiphertext_ReturnsValidationFailure()
    {
        var encrypted = _sut.Encrypt("secret"u8.ToArray(), Key256).Value!;
        encrypted[15] ^= 0xFF; // tamper the ciphertext

        var result = _sut.Decrypt(encrypted, Key256);

        result.IsFailure.Should().BeTrue();
        result.Error.Code.Should().StartWith("Validation");
    }

    [Fact]
    public void Decrypt_WrongKey_ReturnsValidationFailure()
    {
        var encrypted = _sut.Encrypt("secret"u8.ToArray(), Key256).Value!;
        var wrongKey = new byte[32];
        wrongKey[0] = 1;

        var result = _sut.Decrypt(encrypted, wrongKey);

        result.IsFailure.Should().BeTrue();
    }

    [Fact]
    public void Decrypt_TooShortCiphertext_ReturnsValidationFailure()
    {
        var result = _sut.Decrypt(new byte[27], Key256);
        result.IsFailure.Should().BeTrue();
        result.Error.Code.Should().StartWith("Validation");
    }

    [Fact]
    public void Encrypt_TwoCalls_ProduceDifferentCiphertexts()
    {
        var plaintext = "hello"u8.ToArray();
        var c1 = _sut.Encrypt(plaintext, Key256).Value!;
        var c2 = _sut.Encrypt(plaintext, Key256).Value!;

        c1.Should().NotEqual(c2); // Different random nonces
    }

    [Fact]
    public void Encrypt_String_RoundTrip()
    {
        var encrypted = _sut.Encrypt("hello world", "my-secret-key");
        encrypted.IsSuccess.Should().BeTrue();

        var decrypted = _sut.Decrypt(encrypted.Value!, "my-secret-key");
        decrypted.IsSuccess.Should().BeTrue();
        decrypted.Value!.Should().Be("hello world");
    }

    [Fact]
    public void Decrypt_String_WrongKey_ReturnsFailure()
    {
        var encrypted = _sut.Encrypt("hello", "correct-key").Value!;
        var result = _sut.Decrypt(encrypted, "wrong-key");

        result.IsFailure.Should().BeTrue();
    }

    [Fact]
    public void Decrypt_String_InvalidBase64_ReturnsValidationFailure()
    {
        var result = _sut.Decrypt("not-valid-base64!!!", "key");

        result.IsFailure.Should().BeTrue();
        result.Error.Code.Should().StartWith("Validation");
    }
}
