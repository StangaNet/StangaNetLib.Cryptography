using StangaNetLib.Core.Common;

namespace StangaNetLib.Cryptography.Abstractions;

/// <summary>
/// Provides authenticated symmetric encryption and decryption using AES-256-GCM.
/// The ciphertext format is: <c>nonce (12 bytes) || ciphertext || authentication tag (16 bytes)</c>.
/// The authentication tag prevents undetected tampering — decryption fails with a validation error
/// if the data has been modified.
/// </summary>
public interface IEncryptionService
{
    /// <summary>
    /// Encrypts <paramref name="plaintext"/> using AES-GCM with a random 12-byte nonce.
    /// </summary>
    /// <param name="plaintext">The data to encrypt.</param>
    /// <param name="key">
    /// The AES key. Must be exactly 16 (AES-128), 24 (AES-192), or 32 (AES-256) bytes.
    /// </param>
    /// <returns>
    /// Bytes in the format <c>nonce (12) || ciphertext || tag (16)</c>,
    /// or a validation error if the key length is invalid.
    /// </returns>
    Result<byte[]> Encrypt(byte[] plaintext, byte[] key);

    /// <summary>
    /// Decrypts ciphertext produced by <see cref="Encrypt(byte[], byte[])"/>.
    /// </summary>
    /// <param name="ciphertext">Bytes in the format <c>nonce (12) || ciphertext || tag (16)</c>.</param>
    /// <param name="key">The AES key used during encryption. Must be 16, 24, or 32 bytes.</param>
    /// <returns>
    /// The decrypted plaintext bytes; a validation error if the key length is invalid, the ciphertext
    /// is too short, or the authentication tag does not match (tampering detected); or an internal
    /// error on unexpected failures.
    /// </returns>
    Result<byte[]> Decrypt(byte[] ciphertext, byte[] key);

    /// <summary>
    /// Encrypts a UTF-8 string, deriving a 32-byte AES key from <paramref name="keyString"/> via SHA-256.
    /// </summary>
    /// <param name="plaintext">The string to encrypt. Must not be null or empty.</param>
    /// <param name="keyString">The key string from which the AES key is derived. Must not be null or empty.</param>
    /// <returns>A standard Base64-encoded ciphertext string, or a validation error.</returns>
    Result<string> Encrypt(string plaintext, string keyString);

    /// <summary>
    /// Decrypts a Base64-encoded ciphertext string produced by <see cref="Encrypt(string, string)"/>.
    /// </summary>
    /// <param name="ciphertext">The Base64-encoded ciphertext to decrypt.</param>
    /// <param name="keyString">The key string used during encryption.</param>
    /// <returns>
    /// The decrypted UTF-8 string; a validation error if the ciphertext is not valid Base64, too short,
    /// or the authentication tag does not match; or an internal error on unexpected failures.
    /// </returns>
    Result<string> Decrypt(string ciphertext, string keyString);
}
