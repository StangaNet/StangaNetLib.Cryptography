using StangaNetLib.Core.Common;
using StangaNetLib.Cryptography.Models;

namespace StangaNetLib.Cryptography.Abstractions;

/// <summary>Signs and verifies data using HMAC with SHA-2 and SHA-3 hash algorithms.</summary>
public interface IHmacService
{
    /// <summary>Computes an HMAC signature over <paramref name="data"/> using the provided <paramref name="key"/>.</summary>
    /// <param name="data">The data to sign.</param>
    /// <param name="key">The HMAC key bytes. Must not be empty.</param>
    /// <param name="algorithm">The hash algorithm to use. Defaults to <see cref="CryptoHashAlgorithm.SHA256"/>.</param>
    /// <returns>A lowercase hex string of the HMAC, or a validation error if the key is empty.</returns>
    Result<string> Sign(byte[] data, byte[] key, CryptoHashAlgorithm algorithm = CryptoHashAlgorithm.SHA256);

    /// <summary>
    /// Computes an HMAC signature over the UTF-8 representation of <paramref name="data"/>
    /// using the UTF-8 representation of <paramref name="key"/>.
    /// </summary>
    /// <param name="data">The data to sign.</param>
    /// <param name="key">The HMAC key string. Must not be null or empty.</param>
    /// <param name="algorithm">The hash algorithm to use. Defaults to <see cref="CryptoHashAlgorithm.SHA256"/>.</param>
    /// <returns>A lowercase hex string of the HMAC, or a validation error if the key is empty.</returns>
    Result<string> Sign(string data, string key, CryptoHashAlgorithm algorithm = CryptoHashAlgorithm.SHA256);

    /// <summary>
    /// Verifies that <paramref name="data"/> produces <paramref name="expectedSignature"/> with the given
    /// <paramref name="key"/> using a constant-time comparison.
    /// </summary>
    /// <param name="data">The data that was signed.</param>
    /// <param name="expectedSignature">The expected lowercase hex HMAC.</param>
    /// <param name="key">The HMAC key bytes. Must not be empty.</param>
    /// <param name="algorithm">The hash algorithm to use. Defaults to <see cref="CryptoHashAlgorithm.SHA256"/>.</param>
    /// <returns><c>true</c> when the signature matches; a validation error if the key is empty.</returns>
    Result<bool> Verify(byte[] data, string expectedSignature, byte[] key, CryptoHashAlgorithm algorithm = CryptoHashAlgorithm.SHA256);

    /// <summary>
    /// Verifies that the UTF-8 representation of <paramref name="data"/> produces
    /// <paramref name="expectedSignature"/> with the given <paramref name="key"/> using a constant-time comparison.
    /// </summary>
    /// <param name="data">The data that was signed.</param>
    /// <param name="expectedSignature">The expected lowercase hex HMAC.</param>
    /// <param name="key">The HMAC key string. Must not be null or empty.</param>
    /// <param name="algorithm">The hash algorithm to use. Defaults to <see cref="CryptoHashAlgorithm.SHA256"/>.</param>
    /// <returns><c>true</c> when the signature matches; a validation error if the key is empty.</returns>
    Result<bool> Verify(string data, string expectedSignature, string key, CryptoHashAlgorithm algorithm = CryptoHashAlgorithm.SHA256);
}
