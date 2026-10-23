using System.Security.Cryptography;
using System.Text;
using FluentAssertions;
using Microsoft.Extensions.Options;
using StangaNetLib.Cryptography.Helpers;
using StangaNetLib.Cryptography.Implementations;
using StangaNetLib.Cryptography.Models;
using StangaNetLib.Cryptography.Settings;

namespace StangaNetLib.Cryptography.Tests;

public sealed class AtRestEncryptionServiceTests
{
    private static AtRestEncryptionService CreateSut(int pbkdf2Iterations = 100_000)
    {
        var settings = Options.Create(new CryptographySettings
        {
            Pbkdf2Iterations = pbkdf2Iterations,
            DefaultSaltLengthBytes = 16,
            DefaultKeyLengthBytes = 32,
        });
        var kdf = new KeyDerivationService(settings);
        return new AtRestEncryptionService(kdf, settings);
    }

    [Fact]
    public void EncryptBlob_DecryptBlob_RoundTrips()
    {
        var sut = CreateSut();
        var plaintext = Encoding.UTF8.GetBytes("at-rest secret");

        var encrypted = sut.EncryptBlob(plaintext, "correct horse battery staple");
        encrypted.IsSuccess.Should().BeTrue();

        var decrypted = sut.DecryptBlob(encrypted.Value!, "correct horse battery staple");
        decrypted.IsSuccess.Should().BeTrue();
        decrypted.Value!.Should().Equal(plaintext);
    }

    [Fact]
    public void EncryptBlob_DifferentSalts_ProduceDifferentCiphertexts()
    {
        var sut = CreateSut();
        var plaintext = "same plaintext"u8.ToArray();

        var a = sut.EncryptBlob(plaintext, "passphrase").Value!;
        var b = sut.EncryptBlob(plaintext, "passphrase").Value!;

        a.Should().NotEqual(b);
    }

    [Fact]
    public void EncryptBlob_StartsWithSnenMagic()
    {
        var sut = CreateSut();
        var envelope = sut.EncryptBlob("x"u8.ToArray(), "pass").Value!;
        envelope.AsSpan(0, 4).ToArray().Should().Equal("SNEN"u8.ToArray());
    }

    [Fact]
    public void DecryptBlob_WrongPassphrase_Fails()
    {
        var sut = CreateSut();
        var envelope = sut.EncryptBlob("secret"u8.ToArray(), "right").Value!;

        var result = sut.DecryptBlob(envelope, "wrong");
        result.IsFailure.Should().BeTrue();
    }

    [Fact]
    public void DecryptBlob_TamperedCiphertext_Fails()
    {
        var sut = CreateSut();
        var envelope = sut.EncryptBlob("secret"u8.ToArray(), "pass").Value!;
        envelope[^5] ^= 0xFF;

        var result = sut.DecryptBlob(envelope, "pass");
        result.IsFailure.Should().BeTrue();
    }

    [Fact]
    public void EncryptBlobWithHkdf_RoundTrips()
    {
        var sut = CreateSut();
        var ikm = RandomNumberGenerator.GetBytes(32);
        var plaintext = "hkdf blob"u8.ToArray();

        var encrypted = sut.EncryptBlobWithHkdf(plaintext, ikm);
        encrypted.IsSuccess.Should().BeTrue();

        var decrypted = sut.DecryptBlobWithHkdf(encrypted.Value!, ikm);
        decrypted.IsSuccess.Should().BeTrue();
        decrypted.Value!.Should().Equal(plaintext);
    }

    [Fact]
    public void EncryptBlob_WithExplicitPbkdf2Kdf_RoundTrips()
    {
        var sut = CreateSut();
        var plaintext = "explicit"u8.ToArray();

        var encrypted = sut.EncryptBlob(plaintext, "secret", AtRestKdf.Pbkdf2Sha256);
        var decrypted = sut.DecryptBlob(encrypted.Value!, "secret");

        decrypted.Value!.Should().Equal(plaintext);
    }

    [Fact]
    public async Task EncryptStream_DecryptStream_RoundTrips()
    {
        var ct = TestContext.Current.CancellationToken;
        var sut = CreateSut();
        var original = Encoding.UTF8.GetBytes(new string('A', 100_000)); // > 1 frame

        await using var plainIn = new MemoryStream(original);
        await using var cipher = new MemoryStream();
        var enc = await sut.EncryptStreamAsync(plainIn, cipher, "stream-pass", cancellationToken: ct);
        enc.IsSuccess.Should().BeTrue();

        cipher.Position = 0;
        await using var plainOut = new MemoryStream();
        var dec = await sut.DecryptStreamAsync(cipher, plainOut, "stream-pass", cancellationToken: ct);
        dec.IsSuccess.Should().BeTrue();
        plainOut.ToArray().Should().Equal(original);
    }

    [Fact]
    public async Task EncryptStream_TamperedFrame_Fails()
    {
        var ct = TestContext.Current.CancellationToken;
        var sut = CreateSut();
        await using var plainIn = new MemoryStream("hello stream"u8.ToArray());
        await using var cipher = new MemoryStream();
        (await sut.EncryptStreamAsync(plainIn, cipher, "pass", cancellationToken: ct)).IsSuccess.Should().BeTrue();

        var bytes = cipher.ToArray();
        bytes[^20] ^= 0xFF;

        await using var tampered = new MemoryStream(bytes);
        await using var plainOut = new MemoryStream();
        var dec = await sut.DecryptStreamAsync(tampered, plainOut, "pass", cancellationToken: ct);
        dec.IsFailure.Should().BeTrue();
    }

    [Fact]
    public async Task FileEnvelope_WriteAndRead_RoundTrips()
    {
        var ct = TestContext.Current.CancellationToken;
        var sut = CreateSut();
        var dir = Path.Combine(Path.GetTempPath(), "sn-crypto-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(dir);
        try
        {
            var source = Path.Combine(dir, "plain.bin");
            var envelope = Path.Combine(dir, "plain.bin.sn");
            var restored = Path.Combine(dir, "restored.bin");
            await File.WriteAllBytesAsync(source, "file envelope payload"u8.ToArray(), ct);

            var write = await FileEnvelope.WriteAsync(sut, source, envelope, "file-pass", cancellationToken: ct);
            write.IsSuccess.Should().BeTrue();

            var read = await FileEnvelope.ReadAsync(sut, envelope, restored, "file-pass", cancellationToken: ct);
            read.IsSuccess.Should().BeTrue();

            (await File.ReadAllBytesAsync(restored, ct)).Should().Equal(await File.ReadAllBytesAsync(source, ct));
        }
        finally
        {
            Directory.Delete(dir, recursive: true);
        }
    }

    [Fact]
    public void EncryptBlob_EmptyPlaintext_Succeeds()
    {
        var sut = CreateSut();
        var encrypted = sut.EncryptBlob([], "pass");
        encrypted.IsSuccess.Should().BeTrue();

        var decrypted = sut.DecryptBlob(encrypted.Value!, "pass");
        decrypted.IsSuccess.Should().BeTrue();
        decrypted.Value!.Should().BeEmpty();
    }

    [Fact]
    public void EncryptBlob_WithAssociatedData_RequiresMatchingAad()
    {
        var sut = CreateSut();
        var aad = "context"u8.ToArray();
        var envelope = sut.EncryptBlob("data"u8.ToArray(), "pass", aad).Value!;

        sut.DecryptBlob(envelope, "pass", aad).IsSuccess.Should().BeTrue();
        sut.DecryptBlob(envelope, "pass", "other"u8.ToArray()).IsFailure.Should().BeTrue();
        sut.DecryptBlob(envelope, "pass").IsFailure.Should().BeTrue();
    }
}
