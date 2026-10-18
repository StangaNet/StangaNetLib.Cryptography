using System.Security.Cryptography;
using System.Text;
using StangaNetLib.Core.Common;
using StangaNetLib.Core.Guards;
using StangaNetLib.Cryptography.Abstractions;

namespace StangaNetLib.Cryptography.Implementations;

internal sealed class AesGcmEncryptionService : IEncryptionService
{
    private const int NonceSize = 12;
    private const int TagSize = 16;

    public Result<byte[]> Encrypt(byte[] plaintext, byte[] key)
    {
        Guard.Against.Null(plaintext, nameof(plaintext));
        Guard.Against.Null(key, nameof(key));

        if (!IsValidKeySize(key.Length))
            return Result<byte[]>.Failure(
                Error.Validation("key", "AES key must be 16, 24, or 32 bytes (128, 192, or 256 bits)."));

        var nonce = RandomNumberGenerator.GetBytes(NonceSize);
        var ciphertext = new byte[plaintext.Length];
        var tag = new byte[TagSize];

        using var aes = new AesGcm(key, TagSize);
        aes.Encrypt(nonce, plaintext, ciphertext, tag);

        var output = new byte[NonceSize + ciphertext.Length + TagSize];
        nonce.CopyTo(output, 0);
        ciphertext.CopyTo(output, NonceSize);
        tag.CopyTo(output, NonceSize + ciphertext.Length);

        return Result<byte[]>.Success(output);
    }

    public Result<byte[]> Decrypt(byte[] ciphertext, byte[] key)
    {
        Guard.Against.Null(ciphertext, nameof(ciphertext));
        Guard.Against.Null(key, nameof(key));

        if (!IsValidKeySize(key.Length))
            return Result<byte[]>.Failure(
                Error.Validation("key", "AES key must be 16, 24, or 32 bytes (128, 192, or 256 bits)."));

        if (ciphertext.Length < NonceSize + TagSize)
            return Result<byte[]>.Failure(
                Error.Validation("ciphertext", "Ciphertext is too short to contain a valid nonce and tag."));

        var nonce = ciphertext.AsSpan(0, NonceSize);
        var encryptedContent = ciphertext.AsSpan(NonceSize, ciphertext.Length - NonceSize - TagSize);
        var tag = ciphertext.AsSpan(ciphertext.Length - TagSize, TagSize);
        var plaintext = new byte[encryptedContent.Length];

        try
        {
            using var aes = new AesGcm(key, TagSize);
            aes.Decrypt(nonce, encryptedContent, tag, plaintext);
            return Result<byte[]>.Success(plaintext);
        }
        catch (AuthenticationTagMismatchException)
        {
            return Result<byte[]>.Failure(
                Error.Validation("ciphertext", "Authentication tag mismatch — ciphertext may be tampered or the key is incorrect."));
        }
        catch (Exception ex)
        {
            return Result<byte[]>.Failure(Error.Internal($"Decryption failed: {ex.Message}"));
        }
    }

    public Result<string> Encrypt(string plaintext, string keyString)
    {
        Guard.Against.NullOrEmpty(plaintext, nameof(plaintext));
        Guard.Against.NullOrEmpty(keyString, nameof(keyString));

        var key = DeriveKey(keyString);
        return Encrypt(Encoding.UTF8.GetBytes(plaintext), key).Map(Convert.ToBase64String);
    }

    public Result<string> Decrypt(string ciphertext, string keyString)
    {
        Guard.Against.NullOrEmpty(ciphertext, nameof(ciphertext));
        Guard.Against.NullOrEmpty(keyString, nameof(keyString));

        byte[] ciphertextBytes;
        try
        {
            ciphertextBytes = Convert.FromBase64String(ciphertext);
        }
        catch (FormatException)
        {
            return Result<string>.Failure(
                Error.Validation("ciphertext", "Ciphertext is not valid Base64."));
        }

        var key = DeriveKey(keyString);
        return Decrypt(ciphertextBytes, key).Map(b => Encoding.UTF8.GetString(b));
    }

    private static bool IsValidKeySize(int length) => length is 16 or 24 or 32;

    private static byte[] DeriveKey(string keyString) =>
        SHA256.HashData(Encoding.UTF8.GetBytes(keyString));
}
