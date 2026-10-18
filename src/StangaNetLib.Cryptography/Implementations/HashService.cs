using System.Security.Cryptography;
using System.Text;
using StangaNetLib.Core.Guards;
using StangaNetLib.Cryptography.Abstractions;
using StangaNetLib.Cryptography.Models;

namespace StangaNetLib.Cryptography.Implementations;

internal sealed class HashService : IHashService
{
    public string ComputeHash(byte[] data, CryptoHashAlgorithm algorithm = CryptoHashAlgorithm.SHA256)
    {
        Guard.Against.Null(data, nameof(data));
        return Convert.ToHexString(HashRaw(data, algorithm)).ToLowerInvariant();
    }

    public string ComputeHash(string input, CryptoHashAlgorithm algorithm = CryptoHashAlgorithm.SHA256)
    {
        Guard.Against.NullOrEmpty(input, nameof(input));
        return ComputeHash(Encoding.UTF8.GetBytes(input), algorithm);
    }

    public string ComputeHashBase64(byte[] data, CryptoHashAlgorithm algorithm = CryptoHashAlgorithm.SHA256)
    {
        Guard.Against.Null(data, nameof(data));
        return Convert.ToBase64String(HashRaw(data, algorithm));
    }

    public string ComputeHashBase64(string input, CryptoHashAlgorithm algorithm = CryptoHashAlgorithm.SHA256)
    {
        Guard.Against.NullOrEmpty(input, nameof(input));
        return ComputeHashBase64(Encoding.UTF8.GetBytes(input), algorithm);
    }

    public bool VerifyHash(byte[] data, string expectedHash, CryptoHashAlgorithm algorithm = CryptoHashAlgorithm.SHA256)
    {
        Guard.Against.Null(data, nameof(data));
        Guard.Against.NullOrEmpty(expectedHash, nameof(expectedHash));

        var actualHex = Encoding.UTF8.GetBytes(ComputeHash(data, algorithm));
        var expectedHex = Encoding.UTF8.GetBytes(expectedHash.ToLowerInvariant());
        return CryptographicOperations.FixedTimeEquals(actualHex, expectedHex);
    }

    public bool VerifyHash(string input, string expectedHash, CryptoHashAlgorithm algorithm = CryptoHashAlgorithm.SHA256)
    {
        Guard.Against.NullOrEmpty(input, nameof(input));
        return VerifyHash(Encoding.UTF8.GetBytes(input), expectedHash, algorithm);
    }

    public bool VerifyHashBase64(byte[] data, string expectedHashBase64, CryptoHashAlgorithm algorithm = CryptoHashAlgorithm.SHA256)
    {
        Guard.Against.Null(data, nameof(data));
        Guard.Against.NullOrEmpty(expectedHashBase64, nameof(expectedHashBase64));

        var actualBase64 = Encoding.UTF8.GetBytes(ComputeHashBase64(data, algorithm));
        var expectedBytes = Encoding.UTF8.GetBytes(expectedHashBase64);
        return CryptographicOperations.FixedTimeEquals(actualBase64, expectedBytes);
    }

    public bool VerifyHashBase64(string input, string expectedHashBase64, CryptoHashAlgorithm algorithm = CryptoHashAlgorithm.SHA256)
    {
        Guard.Against.NullOrEmpty(input, nameof(input));
        return VerifyHashBase64(Encoding.UTF8.GetBytes(input), expectedHashBase64, algorithm);
    }

    private static byte[] HashRaw(byte[] data, CryptoHashAlgorithm algorithm) => algorithm switch
    {
        CryptoHashAlgorithm.SHA256 => SHA256.HashData(data),
        CryptoHashAlgorithm.SHA384 => SHA384.HashData(data),
        CryptoHashAlgorithm.SHA512 => SHA512.HashData(data),
        CryptoHashAlgorithm.SHA3_256 => SHA3_256.IsSupported
            ? SHA3_256.HashData(data)
            : throw new PlatformNotSupportedException("SHA3-256 is not supported on this platform."),
        CryptoHashAlgorithm.SHA3_384 => SHA3_384.IsSupported
            ? SHA3_384.HashData(data)
            : throw new PlatformNotSupportedException("SHA3-384 is not supported on this platform."),
        CryptoHashAlgorithm.SHA3_512 => SHA3_512.IsSupported
            ? SHA3_512.HashData(data)
            : throw new PlatformNotSupportedException("SHA3-512 is not supported on this platform."),
        _ => throw new ArgumentOutOfRangeException(nameof(algorithm), algorithm, null),
    };
}
