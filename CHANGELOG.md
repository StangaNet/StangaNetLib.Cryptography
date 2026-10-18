# Changelog

All notable changes to **StangaNetLib.Cryptography** are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [1.0.0] - 2026-10-18

### Added
- `IHashService` — SHA-2 / SHA-3 digests (hex and Base64) with constant-time verify.
- `IHmacService` — HMAC-SHA sign/verify returning `Result<T>` from Core.
- `IKeyDerivationService` — PBKDF2 / HKDF and salt generation (`CryptographySettings`).
- `IDigitalSignatureService` — RSA key pair generation, PKCS#1 v1.5 sign/verify.
- `IEncryptionService` — AES-GCM authenticated encrypt/decrypt (nonce || ciphertext || tag).
- `ISecureTokenService` — URL-safe tokens, hex tokens, numeric OTP, secure GUID.
- DI registration (`AddStangaNetLibCryptography`) with options validation.
- Dual targeting `net8.0` / `net9.0`, XML docs, symbols (`snupkg`), package icon, and MSBuild consumer metadata stamp.
- Depends on `StangaNetLib.Core` 1.0.0; Microsoft.Extensions.* pinned to 8.x.
- CI via shared StangaNet reusable workflow (push / PR / manual; publish outside PRs).

[Unreleased]: https://github.com/StangaNet/StangaNetLib.Cryptography/compare/v1.0.0...HEAD
[1.0.0]: https://github.com/StangaNet/StangaNetLib.Cryptography/releases/tag/v1.0.0
