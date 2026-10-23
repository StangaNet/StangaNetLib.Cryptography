# StangaNetLib.Cryptography

[![.NET CI](https://github.com/StangaNet/StangaNetLib.Cryptography/actions/workflows/main.yml/badge.svg)](https://github.com/StangaNet/StangaNetLib.Cryptography/actions/workflows/main.yml)
![NuGet](https://img.shields.io/badge/nuget-1.0.0-blue)
![.NET](https://img.shields.io/badge/.NET-8.0%20%7C%209.0%20%7C%2010.0-512BD4)

Hashing, HMAC, key derivation (PBKDF2/HKDF), AES-GCM encryption, RSA digital signatures, and secure token generation. Failures surface as `Result` / `Result<T>` from [`StangaNetLib.Core`](https://github.com/StangaNet/StangaNetLib.Core).

## Installation

The package is hosted on **GitHub Packages** (pulls Core from the same feed).

```xml
<!-- NuGet.config — source key must match your packageSourceCredentials -->
<configuration>
  <packageSources>
    <add key="StangaNet" value="https://nuget.pkg.github.com/StangaNet/index.json" />
  </packageSources>
</configuration>
```

```xml
<!-- .csproj -->
<PackageReference Include="StangaNetLib.Cryptography" Version="1.0.0" />
```

See [CHANGELOG.md](./CHANGELOG.md) for release history.

## Core Components

| Namespace | Components | Purpose |
|---|---|---|
| `StangaNetLib.Cryptography.Abstractions` | `IHashService`, `IHmacService`, `IKeyDerivationService`, `IDigitalSignatureService`, `IEncryptionService`, `ISecureTokenService` | Public contracts |
| `StangaNetLib.Cryptography.Models` | `CryptoHashAlgorithm`, `KeyDerivationResult`, `RsaKeyPair` | Shared models |
| `StangaNetLib.Cryptography.Settings` | `CryptographySettings` | PBKDF2 defaults |
| `StangaNetLib.Cryptography.Extensions` | `AddStangaNetLibCryptography` | DI |

## Quick Start

```csharp
builder.Services.AddStangaNetLibCryptography(builder.Configuration);

public class MyService(IHashService hash, IEncryptionService enc, ISecureTokenService tokens)
{
    public void Demo()
    {
        var digest = hash.ComputeHash("hello world");
        var cipher = enc.Encrypt("secret", "passphrase");
        var token = tokens.GenerateToken();
    }
}
```

Optional `appsettings.json` (defaults shown):

```json
{
  "CryptographySettings": {
    "Pbkdf2Iterations": 600000,
    "DefaultSaltLengthBytes": 16,
    "DefaultKeyLengthBytes": 32
  }
}
```

## Project Structure

```
StangaNetLib.Cryptography/
├── assets/
│   └── package-icon.png
├── build/
│   └── StangaNetLib.Cryptography.props
├── src/
│   └── StangaNetLib.Cryptography/
└── tests/
    └── StangaNetLib.Cryptography.Tests/
```

## License

Apache-2.0 — see [LICENSE](./LICENSE).
