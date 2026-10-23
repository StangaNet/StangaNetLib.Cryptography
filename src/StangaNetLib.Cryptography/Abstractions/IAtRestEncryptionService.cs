using StangaNetLib.Core.Common;
using StangaNetLib.Cryptography.Models;

namespace StangaNetLib.Cryptography.Abstractions;

/// <summary>
/// Encrypts and decrypts blobs and streams at rest using AES-256-GCM with a versioned
/// envelope that embeds KDF parameters (PBKDF2 or HKDF) and salt.
/// </summary>
public interface IAtRestEncryptionService
{
    /// <summary>
    /// Encrypts <paramref name="plaintext"/> with a key derived from <paramref name="passphrase"/>
    /// via PBKDF2-SHA256 (default iterations from <c>CryptographySettings</c>).
    /// </summary>
    /// <param name="plaintext">Plaintext bytes to encrypt. May be empty.</param>
    /// <param name="passphrase">Passphrase used to derive the AES key. Must not be null or empty.</param>
    /// <param name="associatedData">Optional AAD bound into the GCM tag (not stored in the envelope).</param>
    /// <returns>A versioned envelope (<c>SNEN</c> header + ciphertext), or a validation error.</returns>
    Result<byte[]> EncryptBlob(byte[] plaintext, string passphrase, byte[]? associatedData = null);

    /// <summary>
    /// Encrypts <paramref name="plaintext"/> with a key derived via the specified <paramref name="kdf"/>.
    /// For <see cref="AtRestKdf.Pbkdf2Sha256"/>, <paramref name="secret"/> is treated as a passphrase.
    /// For <see cref="AtRestKdf.HkdfSha256"/>, <paramref name="secret"/> is UTF-8-encoded IKM
    /// (prefer the overload that accepts raw IKM bytes when available).
    /// </summary>
    Result<byte[]> EncryptBlob(
        byte[] plaintext,
        string secret,
        AtRestKdf kdf,
        byte[]? associatedData = null);

    /// <summary>
    /// Encrypts <paramref name="plaintext"/> with HKDF-SHA256 from raw <paramref name="inputKeyMaterial"/>.
    /// </summary>
    Result<byte[]> EncryptBlobWithHkdf(
        byte[] plaintext,
        byte[] inputKeyMaterial,
        byte[]? associatedData = null);

    /// <summary>
    /// Decrypts a blob envelope produced by EncryptBlob / <see cref="EncryptBlobWithHkdf"/>.
    /// </summary>
    /// <param name="envelope">Full envelope bytes including header.</param>
    /// <param name="secret">Passphrase (PBKDF2) or UTF-8 IKM (HKDF string path).</param>
    /// <param name="associatedData">Must match the AAD used at encryption time when provided.</param>
    Result<byte[]> DecryptBlob(byte[] envelope, string secret, byte[]? associatedData = null);

    /// <summary>
    /// Decrypts a blob envelope that was encrypted with HKDF from raw IKM.
    /// </summary>
    Result<byte[]> DecryptBlobWithHkdf(
        byte[] envelope,
        byte[] inputKeyMaterial,
        byte[]? associatedData = null);

    /// <summary>
    /// Encrypts <paramref name="plaintext"/> into <paramref name="ciphertext"/> as a chunked stream envelope
    /// (default frame size 64 KiB of plaintext per AES-GCM frame).
    /// </summary>
    Task<Result> EncryptStreamAsync(
        Stream plaintext,
        Stream ciphertext,
        string passphrase,
        byte[]? associatedData = null,
        CancellationToken cancellationToken = default);

    /// <summary>
    /// Decrypts a chunked stream envelope from <paramref name="ciphertext"/> into <paramref name="plaintext"/>.
    /// </summary>
    Task<Result> DecryptStreamAsync(
        Stream ciphertext,
        Stream plaintext,
        string passphrase,
        byte[]? associatedData = null,
        CancellationToken cancellationToken = default);
}
