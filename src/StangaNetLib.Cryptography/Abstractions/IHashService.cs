using StangaNetLib.Cryptography.Models;

namespace StangaNetLib.Cryptography.Abstractions;

/// <summary>Computes and verifies cryptographic hash digests using SHA-2 and SHA-3 algorithms.</summary>
public interface IHashService
{
    /// <summary>Computes a hex-encoded hash digest of the given byte array.</summary>
    /// <param name="data">The raw bytes to hash.</param>
    /// <param name="algorithm">The hash algorithm to use. Defaults to <see cref="CryptoHashAlgorithm.SHA256"/>.</param>
    /// <returns>A lowercase hex string of the digest.</returns>
    string ComputeHash(byte[] data, CryptoHashAlgorithm algorithm = CryptoHashAlgorithm.SHA256);

    /// <summary>Computes a hex-encoded hash digest of the UTF-8 encoded representation of <paramref name="input"/>.</summary>
    /// <param name="input">The string to hash.</param>
    /// <param name="algorithm">The hash algorithm to use. Defaults to <see cref="CryptoHashAlgorithm.SHA256"/>.</param>
    /// <returns>A lowercase hex string of the digest.</returns>
    string ComputeHash(string input, CryptoHashAlgorithm algorithm = CryptoHashAlgorithm.SHA256);

    /// <summary>Computes a standard Base64-encoded hash digest of the given byte array.</summary>
    /// <param name="data">The raw bytes to hash.</param>
    /// <param name="algorithm">The hash algorithm to use. Defaults to <see cref="CryptoHashAlgorithm.SHA256"/>.</param>
    /// <returns>A standard Base64 string of the digest (with padding).</returns>
    string ComputeHashBase64(byte[] data, CryptoHashAlgorithm algorithm = CryptoHashAlgorithm.SHA256);

    /// <summary>Computes a standard Base64-encoded hash digest of the UTF-8 encoded representation of <paramref name="input"/>.</summary>
    /// <param name="input">The string to hash.</param>
    /// <param name="algorithm">The hash algorithm to use. Defaults to <see cref="CryptoHashAlgorithm.SHA256"/>.</param>
    /// <returns>A standard Base64 string of the digest (with padding).</returns>
    string ComputeHashBase64(string input, CryptoHashAlgorithm algorithm = CryptoHashAlgorithm.SHA256);

    /// <summary>
    /// Verifies that <paramref name="data"/> hashes to <paramref name="expectedHash"/> using a
    /// constant-time comparison to prevent timing side-channel attacks.
    /// </summary>
    /// <param name="data">The raw bytes to hash and compare.</param>
    /// <param name="expectedHash">The expected lowercase hex digest.</param>
    /// <param name="algorithm">The hash algorithm to use. Defaults to <see cref="CryptoHashAlgorithm.SHA256"/>.</param>
    /// <returns><c>true</c> if the computed hash matches <paramref name="expectedHash"/>.</returns>
    bool VerifyHash(byte[] data, string expectedHash, CryptoHashAlgorithm algorithm = CryptoHashAlgorithm.SHA256);

    /// <summary>
    /// Verifies that the UTF-8 encoded representation of <paramref name="input"/> hashes to
    /// <paramref name="expectedHash"/> using a constant-time comparison.
    /// </summary>
    /// <param name="input">The string to hash and compare.</param>
    /// <param name="expectedHash">The expected lowercase hex digest.</param>
    /// <param name="algorithm">The hash algorithm to use. Defaults to <see cref="CryptoHashAlgorithm.SHA256"/>.</param>
    /// <returns><c>true</c> if the computed hash matches <paramref name="expectedHash"/>.</returns>
    bool VerifyHash(string input, string expectedHash, CryptoHashAlgorithm algorithm = CryptoHashAlgorithm.SHA256);

    /// <summary>
    /// Verifies that <paramref name="data"/> hashes to <paramref name="expectedHashBase64"/> (Base64-encoded)
    /// using a constant-time comparison.
    /// </summary>
    /// <param name="data">The raw bytes to hash and compare.</param>
    /// <param name="expectedHashBase64">The expected standard Base64 digest.</param>
    /// <param name="algorithm">The hash algorithm to use. Defaults to <see cref="CryptoHashAlgorithm.SHA256"/>.</param>
    /// <returns><c>true</c> if the computed hash matches <paramref name="expectedHashBase64"/>.</returns>
    bool VerifyHashBase64(byte[] data, string expectedHashBase64, CryptoHashAlgorithm algorithm = CryptoHashAlgorithm.SHA256);

    /// <summary>
    /// Verifies that the UTF-8 encoded representation of <paramref name="input"/> hashes to
    /// <paramref name="expectedHashBase64"/> (Base64-encoded) using a constant-time comparison.
    /// </summary>
    /// <param name="input">The string to hash and compare.</param>
    /// <param name="expectedHashBase64">The expected standard Base64 digest.</param>
    /// <param name="algorithm">The hash algorithm to use. Defaults to <see cref="CryptoHashAlgorithm.SHA256"/>.</param>
    /// <returns><c>true</c> if the computed hash matches <paramref name="expectedHashBase64"/>.</returns>
    bool VerifyHashBase64(string input, string expectedHashBase64, CryptoHashAlgorithm algorithm = CryptoHashAlgorithm.SHA256);
}
