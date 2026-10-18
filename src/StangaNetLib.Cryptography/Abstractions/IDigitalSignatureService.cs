using StangaNetLib.Core.Common;
using StangaNetLib.Cryptography.Models;

namespace StangaNetLib.Cryptography.Abstractions;

/// <summary>Creates RSA key pairs and performs asymmetric digital signing and verification.</summary>
public interface IDigitalSignatureService
{
    /// <summary>
    /// Generates a new RSA key pair.
    /// </summary>
    /// <param name="keySizeInBits">
    /// RSA modulus size in bits. Must be at least 2048 and a multiple of 64.
    /// Defaults to 2048.
    /// </param>
    /// <returns>
    /// An <see cref="RsaKeyPair"/> with PEM-encoded public and private keys,
    /// or a validation error if <paramref name="keySizeInBits"/> is below 2048 or not a multiple of 64.
    /// </returns>
    Result<RsaKeyPair> GenerateKeyPair(int keySizeInBits = 2048);

    /// <summary>
    /// Signs <paramref name="data"/> using the RSA private key and returns a Base64-encoded signature.
    /// Only SHA-2 hash algorithms are supported (<see cref="CryptoHashAlgorithm.SHA256"/>,
    /// <see cref="CryptoHashAlgorithm.SHA384"/>, <see cref="CryptoHashAlgorithm.SHA512"/>).
    /// </summary>
    /// <param name="data">The data to sign.</param>
    /// <param name="privateKeyPem">The PKCS#8 PEM-encoded RSA private key.</param>
    /// <param name="hashAlgorithm">The hash algorithm used during signing. Defaults to <see cref="CryptoHashAlgorithm.SHA256"/>.</param>
    /// <param name="usePss">
    /// When <c>true</c> (default), uses RSA-PSS padding (PKCS#1 v2.1, NIST recommended).
    /// When <c>false</c>, uses the legacy PKCS#1 v1.5 padding.
    /// The same value must be passed to <see cref="Verify"/> when verifying.
    /// </param>
    /// <returns>A Base64-encoded RSA signature, or an internal error if signing fails.</returns>
    Result<string> Sign(byte[] data, string privateKeyPem, CryptoHashAlgorithm hashAlgorithm = CryptoHashAlgorithm.SHA256, bool usePss = true);

    /// <summary>
    /// Verifies an RSA signature against <paramref name="data"/> using the supplied public key.
    /// Only SHA-2 hash algorithms are supported.
    /// </summary>
    /// <param name="data">The data that was signed.</param>
    /// <param name="signature">The Base64-encoded RSA signature to verify.</param>
    /// <param name="publicKeyPem">The SPKI PEM-encoded RSA public key.</param>
    /// <param name="hashAlgorithm">The hash algorithm used during signing. Defaults to <see cref="CryptoHashAlgorithm.SHA256"/>.</param>
    /// <param name="usePss">
    /// When <c>true</c> (default), expects RSA-PSS padding.
    /// When <c>false</c>, expects PKCS#1 v1.5 padding.
    /// Must match the value used in <see cref="Sign"/>.
    /// </param>
    /// <returns>
    /// <c>true</c> when the signature is valid; <c>false</c> when it does not match;
    /// or a validation/internal error if the signature is not valid Base64 or the key cannot be parsed.
    /// </returns>
    Result<bool> Verify(byte[] data, string signature, string publicKeyPem, CryptoHashAlgorithm hashAlgorithm = CryptoHashAlgorithm.SHA256, bool usePss = true);
}
