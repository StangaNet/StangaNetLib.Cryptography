using System.Security.Cryptography;
using System.Text;
using Microsoft.Extensions.Options;
using StangaNetLib.Core.Common;
using StangaNetLib.Core.Guards;
using StangaNetLib.Cryptography.Abstractions;
using StangaNetLib.Cryptography.Models;
using StangaNetLib.Cryptography.Settings;

namespace StangaNetLib.Cryptography.Implementations;

internal sealed class KeyDerivationService : IKeyDerivationService
{
    private readonly CryptographySettings _settings;

    public KeyDerivationService(IOptions<CryptographySettings> options)
    {
        _settings = Guard.Against.Null(options, nameof(options)).Value;
    }

    public Result<KeyDerivationResult> DeriveKeyPbkdf2(
        string password,
        byte[]? salt = null,
        int? iterations = null,
        int keyLengthBytes = 32)
    {
        if (string.IsNullOrEmpty(password))
            return Result<KeyDerivationResult>.Failure(
                Error.Validation("password", "Password must not be null or empty."));

        Guard.Against.NegativeOrZero(keyLengthBytes, nameof(keyLengthBytes));

        var actualSalt = salt ?? GenerateSalt(_settings.DefaultSaltLengthBytes);
        var actualIterations = iterations ?? _settings.Pbkdf2Iterations;

        if (actualIterations < 1)
            return Result<KeyDerivationResult>.Failure(
                Error.Validation("iterations", "Iterations must be greater than zero."));

        var key = Rfc2898DeriveBytes.Pbkdf2(
            Encoding.UTF8.GetBytes(password),
            actualSalt,
            actualIterations,
            HashAlgorithmName.SHA256,
            keyLengthBytes);

        return Result<KeyDerivationResult>.Success(
            new KeyDerivationResult(key, actualSalt, actualIterations, "PBKDF2-SHA256"));
    }

    public Result<byte[]> DeriveKeyHkdf(
        byte[] inputKeyMaterial,
        byte[]? salt = null,
        byte[]? info = null,
        int outputLengthBytes = 32)
    {
        Guard.Against.Null(inputKeyMaterial, nameof(inputKeyMaterial));

        if (inputKeyMaterial.Length == 0)
            return Result<byte[]>.Failure(
                Error.Validation("inputKeyMaterial", "Input key material must not be empty."));

        if (outputLengthBytes <= 0)
            return Result<byte[]>.Failure(
                Error.Validation("outputLengthBytes", "Output length must be greater than zero."));

        var key = HKDF.DeriveKey(HashAlgorithmName.SHA256, inputKeyMaterial, outputLengthBytes, salt, info);
        return Result<byte[]>.Success(key);
    }

    public byte[] GenerateSalt(int lengthBytes = 16)
    {
        Guard.Against.NegativeOrZero(lengthBytes, nameof(lengthBytes));
        return RandomNumberGenerator.GetBytes(lengthBytes);
    }
}
