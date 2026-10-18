using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using StangaNetLib.Cryptography.Abstractions;
using StangaNetLib.Cryptography.Implementations;
using StangaNetLib.Cryptography.Settings;

namespace StangaNetLib.Cryptography.Extensions;

/// <summary>Extension methods for registering <c>StangaNetLib.Cryptography</c> services.</summary>
public static class ServiceCollectionExtensions
{
    /// <summary>
    /// Registers all cryptography services using settings bound from <paramref name="configuration"/>.
    /// </summary>
    /// <remarks>
    /// Add the following section to <c>appsettings.json</c> (all keys are optional — shown values are defaults):
    /// <code>
    /// "CryptographySettings": {
    ///   "Pbkdf2Iterations": 600000,
    ///   "DefaultSaltLengthBytes": 16,
    ///   "DefaultKeyLengthBytes": 32
    /// }
    /// </code>
    /// Then register in <c>Program.cs</c>:
    /// <code>
    /// builder.Services.AddStangaNetLibCryptography(builder.Configuration);
    /// </code>
    /// Inject any of the registered interfaces:
    /// <code>
    /// public class MyService(IHashService hash, IHmacService hmac,
    ///                        IKeyDerivationService kdf, IDigitalSignatureService sig,
    ///                        IEncryptionService enc, ISecureTokenService tokens) { }
    /// </code>
    /// </remarks>
    /// <param name="services">The service collection to register into.</param>
    /// <param name="configuration">Application configuration used to bind <see cref="CryptographySettings"/>.</param>
    /// <returns>The same <see cref="IServiceCollection"/> for chaining.</returns>
    public static IServiceCollection AddStangaNetLibCryptography(
        this IServiceCollection services,
        IConfiguration configuration)
    {
        services.AddOptions<CryptographySettings>()
            .Bind(configuration.GetSection(CryptographySettings.SectionName))
            .ValidateDataAnnotations()
            .ValidateOnStart();

        return RegisterServices(services);
    }

    /// <summary>
    /// Registers all cryptography services using default <see cref="CryptographySettings"/> values.
    /// Suitable for environments where no external configuration is needed.
    /// </summary>
    /// <param name="services">The service collection to register into.</param>
    /// <returns>The same <see cref="IServiceCollection"/> for chaining.</returns>
    public static IServiceCollection AddStangaNetLibCryptography(
        this IServiceCollection services)
    {
        services.AddOptions<CryptographySettings>();
        return RegisterServices(services);
    }

    private static IServiceCollection RegisterServices(IServiceCollection services)
    {
        services.AddSingleton<IHashService, HashService>();
        services.AddSingleton<IHmacService, HmacService>();
        services.AddSingleton<IKeyDerivationService, KeyDerivationService>();
        services.AddSingleton<IDigitalSignatureService, RsaDigitalSignatureService>();
        services.AddSingleton<IEncryptionService, AesGcmEncryptionService>();
        services.AddSingleton<ISecureTokenService, SecureTokenService>();
        return services;
    }
}
