using System.Buffers.Binary;
using System.Security.Cryptography;
using System.Text;
using Microsoft.Extensions.Options;
using StangaNetLib.Core.Common;
using StangaNetLib.Core.Guards;
using StangaNetLib.Cryptography.Abstractions;
using StangaNetLib.Cryptography.Models;
using StangaNetLib.Cryptography.Settings;

namespace StangaNetLib.Cryptography.Implementations;

internal sealed class AtRestEncryptionService : IAtRestEncryptionService
{
    private static readonly byte[] Magic = "SNEN"u8.ToArray();
    private const byte FormatVersion = 1;
    private const byte ModeBlob = 0;
    private const byte ModeStream = 1;
    private const int NonceSize = 12;
    private const int TagSize = 16;
    private const int KeySize = 32;
    private const int DefaultFramePlaintextBytes = 64 * 1024;

    private readonly IKeyDerivationService _kdf;
    private readonly CryptographySettings _settings;

    public AtRestEncryptionService(
        IKeyDerivationService kdf,
        IOptions<CryptographySettings> options)
    {
        _kdf = Guard.Against.Null(kdf, nameof(kdf));
        _settings = Guard.Against.Null(options, nameof(options)).Value;
    }

    public Result<byte[]> EncryptBlob(byte[] plaintext, string passphrase, byte[]? associatedData = null)
        => EncryptBlob(plaintext, passphrase, AtRestKdf.Pbkdf2Sha256, associatedData);

    public Result<byte[]> EncryptBlob(
        byte[] plaintext,
        string secret,
        AtRestKdf kdf,
        byte[]? associatedData = null)
    {
        Guard.Against.Null(plaintext, nameof(plaintext));
        Guard.Against.NullOrEmpty(secret, nameof(secret));

        return kdf switch
        {
            AtRestKdf.Pbkdf2Sha256 => EncryptBlobCore(
                plaintext, DerivePbkdf2Key(secret, salt: null), associatedData),
            AtRestKdf.HkdfSha256 => EncryptBlobWithHkdf(
                plaintext, Encoding.UTF8.GetBytes(secret), associatedData),
            _ => Result<byte[]>.Failure(
                Error.Validation("kdf", $"Unsupported KDF value '{kdf}'.")),
        };
    }

    public Result<byte[]> EncryptBlobWithHkdf(
        byte[] plaintext,
        byte[] inputKeyMaterial,
        byte[]? associatedData = null)
    {
        Guard.Against.Null(plaintext, nameof(plaintext));
        Guard.Against.Null(inputKeyMaterial, nameof(inputKeyMaterial));

        if (inputKeyMaterial.Length == 0)
            return Result<byte[]>.Failure(
                Error.Validation("inputKeyMaterial", "Input key material must not be empty."));

        var salt = _kdf.GenerateSalt(_settings.DefaultSaltLengthBytes);
        var keyResult = _kdf.DeriveKeyHkdf(inputKeyMaterial, salt, info: null, KeySize);
        if (keyResult.IsFailure)
            return Result<byte[]>.Failure(keyResult.Error);

        return EncryptBlobCore(
            plaintext,
            new DerivedKey(keyResult.Value!, salt, Iterations: 0, AtRestKdf.HkdfSha256),
            associatedData);
    }

    public Result<byte[]> DecryptBlob(byte[] envelope, string secret, byte[]? associatedData = null)
    {
        Guard.Against.Null(envelope, nameof(envelope));
        Guard.Against.NullOrEmpty(secret, nameof(secret));

        var parsed = ParseHeader(envelope, expectMode: ModeBlob);
        if (parsed.IsFailure)
            return Result<byte[]>.Failure(parsed.Error);

        var header = parsed.Value!;
        var keyResult = DeriveKeyForDecrypt(header, secret, rawIkm: null);
        if (keyResult.IsFailure)
            return Result<byte[]>.Failure(keyResult.Error);

        return DecryptAesGcm(
            keyResult.Value!,
            header.Nonce,
            header.CiphertextAndTag,
            associatedData);
    }

    public Result<byte[]> DecryptBlobWithHkdf(
        byte[] envelope,
        byte[] inputKeyMaterial,
        byte[]? associatedData = null)
    {
        Guard.Against.Null(envelope, nameof(envelope));
        Guard.Against.Null(inputKeyMaterial, nameof(inputKeyMaterial));

        if (inputKeyMaterial.Length == 0)
            return Result<byte[]>.Failure(
                Error.Validation("inputKeyMaterial", "Input key material must not be empty."));

        var parsed = ParseHeader(envelope, expectMode: ModeBlob);
        if (parsed.IsFailure)
            return Result<byte[]>.Failure(parsed.Error);

        var header = parsed.Value!;
        if (header.Kdf != AtRestKdf.HkdfSha256)
            return Result<byte[]>.Failure(
                Error.Validation("envelope", "Envelope was not encrypted with HKDF."));

        var keyResult = _kdf.DeriveKeyHkdf(inputKeyMaterial, header.Salt, info: null, KeySize);
        if (keyResult.IsFailure)
            return Result<byte[]>.Failure(keyResult.Error);

        return DecryptAesGcm(
            keyResult.Value!,
            header.Nonce,
            header.CiphertextAndTag,
            associatedData);
    }

    public async Task<Result> EncryptStreamAsync(
        Stream plaintext,
        Stream ciphertext,
        string passphrase,
        byte[]? associatedData = null,
        CancellationToken cancellationToken = default)
    {
        Guard.Against.Null(plaintext, nameof(plaintext));
        Guard.Against.Null(ciphertext, nameof(ciphertext));
        Guard.Against.NullOrEmpty(passphrase, nameof(passphrase));

        var derived = DerivePbkdf2Key(passphrase, salt: null);
        if (derived.IsFailure)
            return Result.Failure(derived.Error);

        var keyMaterial = derived.Value!;
        try
        {
            await WriteStreamHeaderAsync(ciphertext, keyMaterial, cancellationToken).ConfigureAwait(false);

            var buffer = new byte[DefaultFramePlaintextBytes];
            int read;
            while ((read = await plaintext.ReadAsync(buffer.AsMemory(0, buffer.Length), cancellationToken)
                       .ConfigureAwait(false)) > 0)
            {
                var framePlain = buffer.AsSpan(0, read).ToArray();
                var nonce = RandomNumberGenerator.GetBytes(NonceSize);
                var cipher = new byte[framePlain.Length];
                var tag = new byte[TagSize];

                using (var aes = new AesGcm(keyMaterial.Key, TagSize))
                {
                    aes.Encrypt(nonce, framePlain, cipher, tag, associatedData);
                }

                var lenBytes = new byte[4];
                BinaryPrimitives.WriteInt32BigEndian(lenBytes, framePlain.Length);
                await ciphertext.WriteAsync(lenBytes, cancellationToken).ConfigureAwait(false);
                await ciphertext.WriteAsync(nonce, cancellationToken).ConfigureAwait(false);
                await ciphertext.WriteAsync(cipher, cancellationToken).ConfigureAwait(false);
                await ciphertext.WriteAsync(tag, cancellationToken).ConfigureAwait(false);
            }

            // EOF marker
            var eof = new byte[4];
            await ciphertext.WriteAsync(eof, cancellationToken).ConfigureAwait(false);
            return Result.Success();
        }
        finally
        {
            CryptographicOperations.ZeroMemory(keyMaterial.Key);
        }
    }

    public async Task<Result> DecryptStreamAsync(
        Stream ciphertext,
        Stream plaintext,
        string passphrase,
        byte[]? associatedData = null,
        CancellationToken cancellationToken = default)
    {
        Guard.Against.Null(ciphertext, nameof(ciphertext));
        Guard.Against.Null(plaintext, nameof(plaintext));
        Guard.Against.NullOrEmpty(passphrase, nameof(passphrase));

        var headerResult = await ReadStreamHeaderAsync(ciphertext, cancellationToken).ConfigureAwait(false);
        if (headerResult.IsFailure)
            return Result.Failure(headerResult.Error);

        var header = headerResult.Value!;
        var keyResult = DeriveKeyForDecrypt(header, passphrase, rawIkm: null);
        if (keyResult.IsFailure)
            return Result.Failure(keyResult.Error);

        var key = keyResult.Value!;
        try
        {
            while (true)
            {
                var lenBuf = new byte[4];
                if (!await ReadExactAsync(ciphertext, lenBuf, cancellationToken).ConfigureAwait(false))
                    return Result.Failure(Error.Validation("ciphertext", "Unexpected end of stream envelope."));

                var plainLen = BinaryPrimitives.ReadInt32BigEndian(lenBuf);
                if (plainLen == 0)
                    return Result.Success();

                if (plainLen < 0 || plainLen > DefaultFramePlaintextBytes * 4)
                    return Result.Failure(Error.Validation("ciphertext", "Invalid stream frame length."));

                var nonce = new byte[NonceSize];
                var cipher = new byte[plainLen];
                var tag = new byte[TagSize];

                if (!await ReadExactAsync(ciphertext, nonce, cancellationToken).ConfigureAwait(false)
                    || !await ReadExactAsync(ciphertext, cipher, cancellationToken).ConfigureAwait(false)
                    || !await ReadExactAsync(ciphertext, tag, cancellationToken).ConfigureAwait(false))
                {
                    return Result.Failure(Error.Validation("ciphertext", "Truncated stream frame."));
                }

                var plain = new byte[plainLen];
                try
                {
                    using var aes = new AesGcm(key, TagSize);
                    aes.Decrypt(nonce, cipher, tag, plain, associatedData);
                }
                catch (AuthenticationTagMismatchException)
                {
                    return Result.Failure(
                        Error.Validation("ciphertext",
                            "Authentication tag mismatch — stream may be tampered or the key is incorrect."));
                }

                await plaintext.WriteAsync(plain, cancellationToken).ConfigureAwait(false);
            }
        }
        finally
        {
            CryptographicOperations.ZeroMemory(key);
        }
    }

    private Result<byte[]> EncryptBlobCore(
        byte[] plaintext,
        Result<DerivedKey> derived,
        byte[]? associatedData)
    {
        if (derived.IsFailure)
            return Result<byte[]>.Failure(derived.Error);

        var keyMaterial = derived.Value!;
        try
        {
            var nonce = RandomNumberGenerator.GetBytes(NonceSize);
            var cipher = new byte[plaintext.Length];
            var tag = new byte[TagSize];

            using (var aes = new AesGcm(keyMaterial.Key, TagSize))
            {
                aes.Encrypt(nonce, plaintext, cipher, tag, associatedData);
            }

            using var ms = new MemoryStream();
            WriteHeader(ms, ModeBlob, keyMaterial.Kdf, keyMaterial.Salt, keyMaterial.Iterations);
            ms.Write(nonce);
            ms.Write(cipher);
            ms.Write(tag);
            return Result<byte[]>.Success(ms.ToArray());
        }
        finally
        {
            CryptographicOperations.ZeroMemory(keyMaterial.Key);
        }
    }

    private Result<DerivedKey> DerivePbkdf2Key(string passphrase, byte[]? salt)
    {
        var result = _kdf.DeriveKeyPbkdf2(
            passphrase,
            salt,
            iterations: null,
            keyLengthBytes: KeySize);

        if (result.IsFailure)
            return Result<DerivedKey>.Failure(result.Error);

        var d = result.Value!;
        return Result<DerivedKey>.Success(
            new DerivedKey(d.Key, d.Salt, d.Iterations, AtRestKdf.Pbkdf2Sha256));
    }

    private Result<byte[]> DeriveKeyForDecrypt(EnvelopeHeader header, string? secret, byte[]? rawIkm)
    {
        return header.Kdf switch
        {
            AtRestKdf.Pbkdf2Sha256 => DerivePbkdf2ForDecrypt(header, secret),
            AtRestKdf.HkdfSha256 => DeriveHkdfForDecrypt(header, secret, rawIkm),
            _ => Result<byte[]>.Failure(
                Error.Validation("envelope", $"Unsupported KDF id '{(byte)header.Kdf}' in envelope.")),
        };
    }

    private Result<byte[]> DerivePbkdf2ForDecrypt(EnvelopeHeader header, string? secret)
    {
        if (string.IsNullOrEmpty(secret))
            return Result<byte[]>.Failure(
                Error.Validation("secret", "Passphrase is required for PBKDF2 envelopes."));

        var result = _kdf.DeriveKeyPbkdf2(secret, header.Salt, header.Iterations, KeySize);
        return result.IsFailure
            ? Result<byte[]>.Failure(result.Error)
            : Result<byte[]>.Success(result.Value!.Key);
    }

    private Result<byte[]> DeriveHkdfForDecrypt(EnvelopeHeader header, string? secret, byte[]? rawIkm)
    {
        byte[] ikm;
        if (rawIkm is { Length: > 0 })
        {
            ikm = rawIkm;
        }
        else if (!string.IsNullOrEmpty(secret))
        {
            ikm = Encoding.UTF8.GetBytes(secret);
        }
        else
        {
            return Result<byte[]>.Failure(
                Error.Validation("secret", "IKM is required for HKDF envelopes."));
        }

        return _kdf.DeriveKeyHkdf(ikm, header.Salt, info: null, KeySize);
    }

    private static Result<byte[]> DecryptAesGcm(
        byte[] key,
        byte[] nonce,
        byte[] ciphertextAndTag,
        byte[]? associatedData)
    {
        if (ciphertextAndTag.Length < TagSize)
            return Result<byte[]>.Failure(
                Error.Validation("envelope", "Ciphertext is too short to contain an authentication tag."));

        var cipherLen = ciphertextAndTag.Length - TagSize;
        var cipher = ciphertextAndTag.AsSpan(0, cipherLen);
        var tag = ciphertextAndTag.AsSpan(cipherLen, TagSize);
        var plain = new byte[cipherLen];

        try
        {
            using var aes = new AesGcm(key, TagSize);
            aes.Decrypt(nonce, cipher, tag, plain, associatedData);
            return Result<byte[]>.Success(plain);
        }
        catch (AuthenticationTagMismatchException)
        {
            return Result<byte[]>.Failure(
                Error.Validation("ciphertext",
                    "Authentication tag mismatch — ciphertext may be tampered or the key is incorrect."));
        }
        finally
        {
            CryptographicOperations.ZeroMemory(key);
        }
    }

    private static void WriteHeader(
        Stream stream,
        byte mode,
        AtRestKdf kdf,
        byte[] salt,
        int iterations)
    {
        stream.Write(Magic);
        stream.WriteByte(FormatVersion);
        stream.WriteByte((byte)kdf);
        stream.WriteByte(mode);
        stream.WriteByte((byte)salt.Length);
        stream.Write(salt);

        Span<byte> iterBytes = stackalloc byte[4];
        BinaryPrimitives.WriteInt32BigEndian(iterBytes, iterations);
        stream.Write(iterBytes);
    }

    private async Task WriteStreamHeaderAsync(
        Stream stream,
        DerivedKey keyMaterial,
        CancellationToken cancellationToken)
    {
        using var ms = new MemoryStream();
        WriteHeader(ms, ModeStream, keyMaterial.Kdf, keyMaterial.Salt, keyMaterial.Iterations);
        await stream.WriteAsync(ms.ToArray(), cancellationToken).ConfigureAwait(false);
    }

    private static Result<EnvelopeHeader> ParseHeader(byte[] envelope, byte expectMode)
    {
        if (envelope.Length < Magic.Length + 1 + 1 + 1 + 1 + 4 + NonceSize + TagSize)
            return Result<EnvelopeHeader>.Failure(
                Error.Validation("envelope", "Envelope is too short."));

        var offset = 0;
        if (!envelope.AsSpan(0, Magic.Length).SequenceEqual(Magic))
            return Result<EnvelopeHeader>.Failure(
                Error.Validation("envelope", "Invalid envelope magic."));

        offset += Magic.Length;
        var version = envelope[offset++];
        if (version != FormatVersion)
            return Result<EnvelopeHeader>.Failure(
                Error.Validation("envelope", $"Unsupported envelope version '{version}'."));

        var kdfByte = envelope[offset++];
        if (kdfByte is not ((byte)AtRestKdf.Pbkdf2Sha256 or (byte)AtRestKdf.HkdfSha256))
            return Result<EnvelopeHeader>.Failure(
                Error.Validation("envelope", $"Unsupported KDF id '{kdfByte}'."));

        var mode = envelope[offset++];
        if (mode != expectMode)
            return Result<EnvelopeHeader>.Failure(
                Error.Validation("envelope", $"Unexpected envelope mode '{mode}'."));

        var saltLen = envelope[offset++];
        if (offset + saltLen + 4 > envelope.Length)
            return Result<EnvelopeHeader>.Failure(
                Error.Validation("envelope", "Envelope truncated while reading salt."));

        var salt = envelope.AsSpan(offset, saltLen).ToArray();
        offset += saltLen;

        var iterations = BinaryPrimitives.ReadInt32BigEndian(envelope.AsSpan(offset, 4));
        offset += 4;

        if (mode == ModeBlob)
        {
            if (offset + NonceSize + TagSize > envelope.Length)
                return Result<EnvelopeHeader>.Failure(
                    Error.Validation("envelope", "Envelope truncated while reading ciphertext."));

            var nonce = envelope.AsSpan(offset, NonceSize).ToArray();
            offset += NonceSize;
            var ciphertextAndTag = envelope.AsSpan(offset).ToArray();

            return Result<EnvelopeHeader>.Success(new EnvelopeHeader(
                (AtRestKdf)kdfByte, mode, salt, iterations, nonce, ciphertextAndTag));
        }

        return Result<EnvelopeHeader>.Success(new EnvelopeHeader(
            (AtRestKdf)kdfByte, mode, salt, iterations, Nonce: [], CiphertextAndTag: []));
    }

    private static async Task<Result<EnvelopeHeader>> ReadStreamHeaderAsync(
        Stream stream,
        CancellationToken cancellationToken)
    {
        var fixedPrefix = new byte[Magic.Length + 1 + 1 + 1 + 1];
        if (!await ReadExactAsync(stream, fixedPrefix, cancellationToken).ConfigureAwait(false))
            return Result<EnvelopeHeader>.Failure(
                Error.Validation("ciphertext", "Stream header is truncated."));

        if (!fixedPrefix.AsSpan(0, Magic.Length).SequenceEqual(Magic))
            return Result<EnvelopeHeader>.Failure(
                Error.Validation("ciphertext", "Invalid stream envelope magic."));

        var version = fixedPrefix[Magic.Length];
        if (version != FormatVersion)
            return Result<EnvelopeHeader>.Failure(
                Error.Validation("ciphertext", $"Unsupported envelope version '{version}'."));

        var kdfByte = fixedPrefix[Magic.Length + 1];
        var mode = fixedPrefix[Magic.Length + 2];
        var saltLen = fixedPrefix[Magic.Length + 3];

        if (mode != ModeStream)
            return Result<EnvelopeHeader>.Failure(
                Error.Validation("ciphertext", "Not a stream envelope."));

        if (kdfByte is not ((byte)AtRestKdf.Pbkdf2Sha256 or (byte)AtRestKdf.HkdfSha256))
            return Result<EnvelopeHeader>.Failure(
                Error.Validation("ciphertext", $"Unsupported KDF id '{kdfByte}'."));

        var salt = new byte[saltLen];
        var iterBytes = new byte[4];
        if (!await ReadExactAsync(stream, salt, cancellationToken).ConfigureAwait(false)
            || !await ReadExactAsync(stream, iterBytes, cancellationToken).ConfigureAwait(false))
        {
            return Result<EnvelopeHeader>.Failure(
                Error.Validation("ciphertext", "Stream header is truncated."));
        }

        var iterations = BinaryPrimitives.ReadInt32BigEndian(iterBytes);
        return Result<EnvelopeHeader>.Success(new EnvelopeHeader(
            (AtRestKdf)kdfByte, mode, salt, iterations, Nonce: [], CiphertextAndTag: []));
    }

    private static async Task<bool> ReadExactAsync(
        Stream stream,
        byte[] buffer,
        CancellationToken cancellationToken)
    {
        var offset = 0;
        while (offset < buffer.Length)
        {
            var read = await stream.ReadAsync(buffer.AsMemory(offset, buffer.Length - offset), cancellationToken)
                .ConfigureAwait(false);
            if (read == 0)
                return false;
            offset += read;
        }

        return true;
    }

    private sealed record DerivedKey(byte[] Key, byte[] Salt, int Iterations, AtRestKdf Kdf);

    private sealed record EnvelopeHeader(
        AtRestKdf Kdf,
        byte Mode,
        byte[] Salt,
        int Iterations,
        byte[] Nonce,
        byte[] CiphertextAndTag);
}
