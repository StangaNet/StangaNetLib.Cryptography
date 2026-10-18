namespace StangaNetLib.Cryptography.Models;

/// <summary>
/// Identifies the cryptographic hash algorithm to use.
/// SHA-3 variants require platform support — check <c>SHA3_256.IsSupported</c>
/// (available from .NET 8) before using them in a portable application.
/// SHA-3 is not supported by <see cref="StangaNetLib.Cryptography.Abstractions.IDigitalSignatureService"/>.
/// </summary>
public enum CryptoHashAlgorithm
{
    /// <summary>SHA-2 256-bit digest (32 bytes output).</summary>
    SHA256,

    /// <summary>SHA-2 384-bit digest (48 bytes output).</summary>
    SHA384,

    /// <summary>SHA-2 512-bit digest (64 bytes output).</summary>
    SHA512,

    /// <summary>
    /// SHA-3 256-bit digest (32 bytes output).
    /// Requires <c>SHA3_256.IsSupported == true</c>; throws <see cref="PlatformNotSupportedException"/> otherwise.
    /// </summary>
    SHA3_256,

    /// <summary>
    /// SHA-3 384-bit digest (48 bytes output).
    /// Requires <c>SHA3_384.IsSupported == true</c>; throws <see cref="PlatformNotSupportedException"/> otherwise.
    /// </summary>
    SHA3_384,

    /// <summary>
    /// SHA-3 512-bit digest (64 bytes output).
    /// Requires <c>SHA3_512.IsSupported == true</c>; throws <see cref="PlatformNotSupportedException"/> otherwise.
    /// </summary>
    SHA3_512,
}
