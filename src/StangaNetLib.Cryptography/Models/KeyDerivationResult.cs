namespace StangaNetLib.Cryptography.Models;

/// <summary>
/// Contains the output of a PBKDF2 key derivation operation.
/// Store <see cref="Salt"/>, <see cref="Iterations"/>, and <see cref="Algorithm"/> alongside the
/// <see cref="Key"/> so the derivation can be reproduced identically for verification.
/// </summary>
/// <param name="Key">The derived key bytes.</param>
/// <param name="Salt">The salt used during derivation.</param>
/// <param name="Iterations">The number of PBKDF2 iterations applied.</param>
/// <param name="Algorithm">The algorithm identifier (e.g. <c>PBKDF2-SHA256</c>).</param>
public sealed record KeyDerivationResult(
    byte[] Key,
    byte[] Salt,
    int Iterations,
    string Algorithm);
