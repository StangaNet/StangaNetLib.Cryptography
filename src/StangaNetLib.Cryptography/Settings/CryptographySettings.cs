using System.ComponentModel.DataAnnotations;

namespace StangaNetLib.Cryptography.Settings;

/// <summary>Configuration options for <c>StangaNetLib.Cryptography</c> services.</summary>
public sealed class CryptographySettings
{
    /// <summary>Configuration section name used when binding from <c>appsettings.json</c>.</summary>
    public const string SectionName = "CryptographySettings";

    /// <summary>
    /// Number of PBKDF2 iterations. Must be at least 100 000.
    /// OWASP recommends 600 000 for PBKDF2-SHA256 as of 2023.
    /// </summary>
    [Range(100_000, int.MaxValue, ErrorMessage = "Pbkdf2Iterations must be at least 100 000.")]
    public int Pbkdf2Iterations { get; init; } = 600_000;

    /// <summary>Default salt length in bytes used when no explicit salt is provided to PBKDF2.</summary>
    [Range(8, 64, ErrorMessage = "DefaultSaltLengthBytes must be between 8 and 64.")]
    public int DefaultSaltLengthBytes { get; init; } = 16;

    /// <summary>Default derived key length in bytes for PBKDF2 when <c>keyLengthBytes</c> is not specified.</summary>
    [Range(16, 64, ErrorMessage = "DefaultKeyLengthBytes must be between 16 and 64.")]
    public int DefaultKeyLengthBytes { get; init; } = 32;
}
