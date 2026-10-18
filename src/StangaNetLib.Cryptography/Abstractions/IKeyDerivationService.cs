using StangaNetLib.Core.Common;
using StangaNetLib.Cryptography.Models;

namespace StangaNetLib.Cryptography.Abstractions;

/// <summary>Derives cryptographic keys from passwords or raw key material.</summary>
public interface IKeyDerivationService
{
    /// <summary>
    /// Derives a key from <paramref name="password"/> using PBKDF2-SHA256.
    /// When <paramref name="salt"/> is omitted a cryptographically random salt is generated automatically.
    /// </summary>
    /// <param name="password">The password to derive from. Must not be null or empty.</param>
    /// <param name="salt">
    /// Optional salt bytes. When <c>null</c> a random salt of the length configured in
    /// <c>CryptographySettings.DefaultSaltLengthBytes</c> is generated.
    /// </param>
    /// <param name="iterations">
    /// Optional PBKDF2 iteration count. When <c>null</c> the value from
    /// <c>CryptographySettings.Pbkdf2Iterations</c> is used.
    /// </param>
    /// <param name="keyLengthBytes">Desired output key length in bytes. Default is 32 (256 bits).</param>
    /// <returns>
    /// A <see cref="KeyDerivationResult"/> containing the derived key, the salt used, the iteration
    /// count, and the algorithm identifier; or a validation error if <paramref name="password"/> is empty.
    /// </returns>
    Result<KeyDerivationResult> DeriveKeyPbkdf2(
        string password,
        byte[]? salt = null,
        int? iterations = null,
        int keyLengthBytes = 32);

    /// <summary>
    /// Expands <paramref name="inputKeyMaterial"/> into a derived key using HKDF-SHA256 (RFC 5869).
    /// Suitable for deriving multiple sub-keys from a master secret.
    /// </summary>
    /// <param name="inputKeyMaterial">The source key material. Must not be null or empty.</param>
    /// <param name="salt">Optional salt. When <c>null</c> the HKDF zero-salt is used.</param>
    /// <param name="info">Optional context and application-specific information.</param>
    /// <param name="outputLengthBytes">Desired output length in bytes. Default is 32 (256 bits).</param>
    /// <returns>
    /// The derived key bytes, or a validation error if <paramref name="inputKeyMaterial"/> is empty
    /// or <paramref name="outputLengthBytes"/> is not positive.
    /// </returns>
    Result<byte[]> DeriveKeyHkdf(
        byte[] inputKeyMaterial,
        byte[]? salt = null,
        byte[]? info = null,
        int outputLengthBytes = 32);

    /// <summary>Generates a cryptographically random salt.</summary>
    /// <param name="lengthBytes">The salt length in bytes. Default is 16 (128 bits).</param>
    /// <returns>A byte array filled with random data.</returns>
    byte[] GenerateSalt(int lengthBytes = 16);
}
