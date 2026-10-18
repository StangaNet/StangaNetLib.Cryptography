using System.Security.Cryptography;
using StangaNetLib.Core.Guards;
using StangaNetLib.Cryptography.Abstractions;

namespace StangaNetLib.Cryptography.Implementations;

internal sealed class SecureTokenService : ISecureTokenService
{
    public string GenerateToken(int byteLength = 32)
    {
        Guard.Against.NegativeOrZero(byteLength, nameof(byteLength));
        return Base64UrlEncode(RandomNumberGenerator.GetBytes(byteLength));
    }

    public string GenerateHexToken(int byteLength = 32)
    {
        Guard.Against.NegativeOrZero(byteLength, nameof(byteLength));
        return Convert.ToHexString(RandomNumberGenerator.GetBytes(byteLength)).ToLowerInvariant();
    }

    public string GenerateNumericOtp(int digits = 6)
    {
        Guard.Against.OutOfRange(digits, nameof(digits), 4, 12);

        // Rejection sampling eliminates modulo bias for non-power-of-2 ranges.
        var max = (uint)Math.Pow(10, digits);
        var limit = uint.MaxValue - (uint.MaxValue % max);
        uint value;
        do
        {
            value = BitConverter.ToUInt32(RandomNumberGenerator.GetBytes(4));
        } while (value >= limit);

        return (value % max).ToString().PadLeft(digits, '0');
    }

    public Guid GenerateSecureGuid()
    {
        var bytes = RandomNumberGenerator.GetBytes(16);

        // RFC 4122 §4.4 — .NET Guid stores Data3 little-endian, so the version nibble lives in bytes[7].
        bytes[7] = (byte)((bytes[7] & 0x0f) | 0x40);
        bytes[8] = (byte)((bytes[8] & 0x3f) | 0x80);

        return new Guid(bytes);
    }

    public byte[] GenerateRandomBytes(int count)
    {
        Guard.Against.NegativeOrZero(count, nameof(count));
        return RandomNumberGenerator.GetBytes(count);
    }

    private static string Base64UrlEncode(byte[] bytes) =>
        Convert.ToBase64String(bytes)
            .TrimEnd('=')
            .Replace('+', '-')
            .Replace('/', '_');
}
