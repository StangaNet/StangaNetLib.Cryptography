namespace StangaNetLib.Cryptography.Models;

/// <summary>Key-derivation algorithm used when encrypting data at rest from a passphrase or IKM.</summary>
public enum AtRestKdf : byte
{
    /// <summary>PBKDF2-SHA256 (passphrase + salt + iterations).</summary>
    Pbkdf2Sha256 = 1,

    /// <summary>HKDF-SHA256 (raw input key material + optional salt).</summary>
    HkdfSha256 = 2,
}
