namespace StangaNetLib.Cryptography.Models;

/// <summary>
/// Holds an RSA key pair in PEM-encoded format.
/// <see cref="PublicKeyPem"/> is safe to share; <see cref="PrivateKeyPem"/> must be kept secret.
/// </summary>
/// <param name="PublicKeyPem">SPKI-encoded public key in PEM format.</param>
/// <param name="PrivateKeyPem">PKCS#8-encoded private key in PEM format.</param>
public sealed record RsaKeyPair(
    string PublicKeyPem,
    string PrivateKeyPem);
