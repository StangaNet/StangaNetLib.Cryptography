using StangaNetLib.Core.Common;
using StangaNetLib.Core.Guards;
using StangaNetLib.Cryptography.Abstractions;

namespace StangaNetLib.Cryptography.Helpers;

/// <summary>
/// File-path helpers that wrap <see cref="IAtRestEncryptionService"/> stream APIs
/// for portable encrypted file envelopes.
/// </summary>
public static class FileEnvelope
{
    /// <summary>
    /// Encrypts the file at <paramref name="sourcePath"/> into a new envelope file at
    /// <paramref name="destinationPath"/> using PBKDF2 + AES-GCM.
    /// </summary>
    public static async Task<Result> WriteAsync(
        IAtRestEncryptionService encryption,
        string sourcePath,
        string destinationPath,
        string passphrase,
        byte[]? associatedData = null,
        CancellationToken cancellationToken = default)
    {
        Guard.Against.Null(encryption, nameof(encryption));
        Guard.Against.NullOrWhiteSpace(sourcePath, nameof(sourcePath));
        Guard.Against.NullOrWhiteSpace(destinationPath, nameof(destinationPath));
        Guard.Against.NullOrEmpty(passphrase, nameof(passphrase));

        await using var input = File.OpenRead(sourcePath);
        await using var output = File.Create(destinationPath);
        return await encryption.EncryptStreamAsync(
            input, output, passphrase, associatedData, cancellationToken).ConfigureAwait(false);
    }

    /// <summary>
    /// Decrypts the envelope file at <paramref name="sourcePath"/> into
    /// <paramref name="destinationPath"/>.
    /// </summary>
    public static async Task<Result> ReadAsync(
        IAtRestEncryptionService encryption,
        string sourcePath,
        string destinationPath,
        string passphrase,
        byte[]? associatedData = null,
        CancellationToken cancellationToken = default)
    {
        Guard.Against.Null(encryption, nameof(encryption));
        Guard.Against.NullOrWhiteSpace(sourcePath, nameof(sourcePath));
        Guard.Against.NullOrWhiteSpace(destinationPath, nameof(destinationPath));
        Guard.Against.NullOrEmpty(passphrase, nameof(passphrase));

        await using var input = File.OpenRead(sourcePath);
        await using var output = File.Create(destinationPath);
        return await encryption.DecryptStreamAsync(
            input, output, passphrase, associatedData, cancellationToken).ConfigureAwait(false);
    }
}
