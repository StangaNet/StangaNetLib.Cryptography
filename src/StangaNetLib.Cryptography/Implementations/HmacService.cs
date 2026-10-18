using System.Security.Cryptography;
using System.Text;
using StangaNetLib.Core.Common;
using StangaNetLib.Core.Guards;
using StangaNetLib.Cryptography.Abstractions;
using StangaNetLib.Cryptography.Models;

namespace StangaNetLib.Cryptography.Implementations;

internal sealed class HmacService : IHmacService
{
    public Result<string> Sign(byte[] data, byte[] key, CryptoHashAlgorithm algorithm = CryptoHashAlgorithm.SHA256)
    {
        Guard.Against.Null(data, nameof(data));
        Guard.Against.Null(key, nameof(key));

        if (key.Length == 0)
            return Result<string>.Failure(Error.Validation("key", "HMAC key must not be empty."));

        var hash = ComputeHmac(data, key, algorithm);
        return Result<string>.Success(Convert.ToHexString(hash).ToLowerInvariant());
    }

    public Result<string> Sign(string data, string key, CryptoHashAlgorithm algorithm = CryptoHashAlgorithm.SHA256)
    {
        Guard.Against.Null(data, nameof(data));
        Guard.Against.NullOrEmpty(key, nameof(key));

        return Sign(Encoding.UTF8.GetBytes(data), Encoding.UTF8.GetBytes(key), algorithm);
    }

    public Result<bool> Verify(byte[] data, string expectedSignature, byte[] key, CryptoHashAlgorithm algorithm = CryptoHashAlgorithm.SHA256)
    {
        Guard.Against.Null(data, nameof(data));
        Guard.Against.NullOrEmpty(expectedSignature, nameof(expectedSignature));
        Guard.Against.Null(key, nameof(key));

        if (key.Length == 0)
            return Result<bool>.Failure(Error.Validation("key", "HMAC key must not be empty."));

        var actualHash = ComputeHmac(data, key, algorithm);
        var actualHex = Encoding.UTF8.GetBytes(Convert.ToHexString(actualHash).ToLowerInvariant());
        var expectedHex = Encoding.UTF8.GetBytes(expectedSignature.ToLowerInvariant());
        return Result<bool>.Success(CryptographicOperations.FixedTimeEquals(actualHex, expectedHex));
    }

    public Result<bool> Verify(string data, string expectedSignature, string key, CryptoHashAlgorithm algorithm = CryptoHashAlgorithm.SHA256)
    {
        Guard.Against.Null(data, nameof(data));
        Guard.Against.NullOrEmpty(key, nameof(key));

        return Verify(Encoding.UTF8.GetBytes(data), expectedSignature, Encoding.UTF8.GetBytes(key), algorithm);
    }

    private static byte[] ComputeHmac(byte[] data, byte[] key, CryptoHashAlgorithm algorithm) => algorithm switch
    {
        CryptoHashAlgorithm.SHA256 => HMACSHA256.HashData(key, data),
        CryptoHashAlgorithm.SHA384 => HMACSHA384.HashData(key, data),
        CryptoHashAlgorithm.SHA512 => HMACSHA512.HashData(key, data),
        CryptoHashAlgorithm.SHA3_256 => HMACSHA3_256.IsSupported
            ? HMACSHA3_256.HashData(key, data)
            : throw new PlatformNotSupportedException("HMAC-SHA3-256 is not supported on this platform."),
        CryptoHashAlgorithm.SHA3_384 => HMACSHA3_384.IsSupported
            ? HMACSHA3_384.HashData(key, data)
            : throw new PlatformNotSupportedException("HMAC-SHA3-384 is not supported on this platform."),
        CryptoHashAlgorithm.SHA3_512 => HMACSHA3_512.IsSupported
            ? HMACSHA3_512.HashData(key, data)
            : throw new PlatformNotSupportedException("HMAC-SHA3-512 is not supported on this platform."),
        _ => throw new ArgumentOutOfRangeException(nameof(algorithm), algorithm, null),
    };
}
