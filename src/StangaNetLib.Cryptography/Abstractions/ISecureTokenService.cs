namespace StangaNetLib.Cryptography.Abstractions;

/// <summary>Generates cryptographically secure random tokens, OTPs, and identifiers.</summary>
public interface ISecureTokenService
{
    /// <summary>
    /// Generates a URL-safe Base64-encoded token backed by <paramref name="byteLength"/> random bytes.
    /// Padding characters (<c>=</c>) are omitted and <c>+</c>/<c>/</c> are replaced with <c>-</c>/<c>_</c>.
    /// </summary>
    /// <param name="byteLength">Number of random bytes to generate. Default is 32 (256 bits).</param>
    /// <returns>A URL-safe Base64 string.</returns>
    string GenerateToken(int byteLength = 32);

    /// <summary>Generates a lowercase hexadecimal token backed by <paramref name="byteLength"/> random bytes.</summary>
    /// <param name="byteLength">Number of random bytes to generate. Default is 32 (256 bits).</param>
    /// <returns>A lowercase hex string of length <c>byteLength * 2</c>.</returns>
    string GenerateHexToken(int byteLength = 32);

    /// <summary>
    /// Generates a numeric one-time password of exactly <paramref name="digits"/> digits using
    /// rejection sampling to eliminate modulo bias.
    /// </summary>
    /// <param name="digits">Number of digits. Must be between 4 and 12. Default is 6.</param>
    /// <returns>A zero-padded numeric string of length <paramref name="digits"/>.</returns>
    string GenerateNumericOtp(int digits = 6);

    /// <summary>
    /// Generates a cryptographically random UUID v4
    /// (RFC 4122 variant bits set, 122 random bits).
    /// </summary>
    /// <returns>A random <see cref="Guid"/>.</returns>
    Guid GenerateSecureGuid();

    /// <summary>Generates <paramref name="count"/> cryptographically random bytes.</summary>
    /// <param name="count">Number of bytes to generate. Must be greater than zero.</param>
    /// <returns>A byte array of length <paramref name="count"/> filled with random data.</returns>
    byte[] GenerateRandomBytes(int count);
}
