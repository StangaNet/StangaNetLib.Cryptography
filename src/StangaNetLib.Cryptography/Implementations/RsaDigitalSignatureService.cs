using System.Security.Cryptography;
using StangaNetLib.Core.Common;
using StangaNetLib.Core.Guards;
using StangaNetLib.Cryptography.Abstractions;
using StangaNetLib.Cryptography.Models;

namespace StangaNetLib.Cryptography.Implementations;

internal sealed class RsaDigitalSignatureService : IDigitalSignatureService
{
    public Result<RsaKeyPair> GenerateKeyPair(int keySizeInBits = 2048)
    {
        if (keySizeInBits < 2048)
            return Result<RsaKeyPair>.Failure(
                Error.Validation("keySizeInBits", "RSA key size must be at least 2048 bits."));

        if (keySizeInBits % 64 != 0)
            return Result<RsaKeyPair>.Failure(
                Error.Validation("keySizeInBits", "RSA key size must be a multiple of 64 bits."));

        using var rsa = RSA.Create(keySizeInBits);
        return Result<RsaKeyPair>.Success(new RsaKeyPair(
            rsa.ExportSubjectPublicKeyInfoPem(),
            rsa.ExportPkcs8PrivateKeyPem()));
    }

    public Result<string> Sign(byte[] data, string privateKeyPem, CryptoHashAlgorithm hashAlgorithm = CryptoHashAlgorithm.SHA256, bool usePss = true)
    {
        Guard.Against.Null(data, nameof(data));
        Guard.Against.NullOrWhiteSpace(privateKeyPem, nameof(privateKeyPem));

        try
        {
            using var rsa = RSA.Create();
            rsa.ImportFromPem(privateKeyPem);
            var padding = usePss ? RSASignaturePadding.Pss : RSASignaturePadding.Pkcs1;
            var signature = rsa.SignData(data, ToHashAlgorithmName(hashAlgorithm), padding);
            return Result<string>.Success(Convert.ToBase64String(signature));
        }
        catch (Exception ex)
        {
            return Result<string>.Failure(Error.Internal($"RSA signing failed: {ex.Message}"));
        }
    }

    public Result<bool> Verify(byte[] data, string signature, string publicKeyPem, CryptoHashAlgorithm hashAlgorithm = CryptoHashAlgorithm.SHA256, bool usePss = true)
    {
        Guard.Against.Null(data, nameof(data));
        Guard.Against.NullOrWhiteSpace(signature, nameof(signature));
        Guard.Against.NullOrWhiteSpace(publicKeyPem, nameof(publicKeyPem));

        byte[] signatureBytes;
        try
        {
            signatureBytes = Convert.FromBase64String(signature);
        }
        catch (FormatException)
        {
            return Result<bool>.Failure(Error.Validation("signature", "Signature is not valid Base64."));
        }

        try
        {
            using var rsa = RSA.Create();
            rsa.ImportFromPem(publicKeyPem);
            var padding = usePss ? RSASignaturePadding.Pss : RSASignaturePadding.Pkcs1;
            var isValid = rsa.VerifyData(data, signatureBytes, ToHashAlgorithmName(hashAlgorithm), padding);
            return Result<bool>.Success(isValid);
        }
        catch (Exception ex)
        {
            return Result<bool>.Failure(Error.Internal($"RSA verification failed: {ex.Message}"));
        }
    }

    private static HashAlgorithmName ToHashAlgorithmName(CryptoHashAlgorithm algorithm) => algorithm switch
    {
        CryptoHashAlgorithm.SHA256 => HashAlgorithmName.SHA256,
        CryptoHashAlgorithm.SHA384 => HashAlgorithmName.SHA384,
        CryptoHashAlgorithm.SHA512 => HashAlgorithmName.SHA512,
        _ => throw new ArgumentOutOfRangeException(nameof(algorithm), algorithm,
            "Only SHA-2 algorithms (SHA256, SHA384, SHA512) are supported for RSA signing."),
    };
}
