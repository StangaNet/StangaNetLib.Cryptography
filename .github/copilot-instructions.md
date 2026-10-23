# StangaNetLib.Cryptography — Copilot instructions

- Cryptographic helpers: hashing (SHA-2/SHA-3), HMAC, PBKDF2/HKDF, AES-GCM, RSA signatures, secure tokens.
- Prefer `Result` / `Result<T>` and `Guard` from `StangaNetLib.Core` — do not reintroduce local Result/Guard types.
- Keep public APIs documented (`///`) and options-driven via `CryptographySettings`.
- DI: `AddStangaNetLibCryptography` (with or without `IConfiguration`).
- Match existing naming, file-scoped namespaces, and EditorConfig / Roslyn conventions.
- Tests use xUnit v3 + FluentAssertions; cover `net8.0`, `net9.0`, and `net10.0` when changing shared behavior.
- Never weaken constant-time comparisons or reduce PBKDF2 iteration floors without an explicit security review.
