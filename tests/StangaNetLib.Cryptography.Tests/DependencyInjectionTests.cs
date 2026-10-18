using FluentAssertions;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using StangaNetLib.Cryptography.Abstractions;
using StangaNetLib.Cryptography.Extensions;

namespace StangaNetLib.Cryptography.Tests;

public sealed class DependencyInjectionTests
{
    [Fact]
    public void AddStangaNetLibCryptography_registers_all_services()
    {
        var services = new ServiceCollection();
        services.AddStangaNetLibCryptography();

        using var sp = services.BuildServiceProvider();

        sp.GetRequiredService<IHashService>().Should().NotBeNull();
        sp.GetRequiredService<IHmacService>().Should().NotBeNull();
        sp.GetRequiredService<IKeyDerivationService>().Should().NotBeNull();
        sp.GetRequiredService<IDigitalSignatureService>().Should().NotBeNull();
        sp.GetRequiredService<IEncryptionService>().Should().NotBeNull();
        sp.GetRequiredService<ISecureTokenService>().Should().NotBeNull();
    }

    [Fact]
    public void AddStangaNetLibCryptography_with_configuration_binds_settings()
    {
        var config = new ConfigurationBuilder()
            .AddInMemoryCollection(new Dictionary<string, string?>
            {
                ["CryptographySettings:Pbkdf2Iterations"] = "200000",
                ["CryptographySettings:DefaultSaltLengthBytes"] = "16",
                ["CryptographySettings:DefaultKeyLengthBytes"] = "32",
            })
            .Build();

        var services = new ServiceCollection();
        services.AddStangaNetLibCryptography(config);

        using var sp = services.BuildServiceProvider();
        sp.GetRequiredService<IKeyDerivationService>().Should().NotBeNull();
    }
}
