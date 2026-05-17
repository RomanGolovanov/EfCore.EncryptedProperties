using System.Data.Common;
using System.Security.Cryptography;
using Azure.Core;
using EfCore.EncryptedProperties.Abstractions;
using EfCore.EncryptedProperties.Configuration;
using EfCore.EncryptedProperties.Cryptography;
using EfCore.EncryptedProperties.Infrastructure;
using EfCore.EncryptedProperties.Interceptors;
using EfCore.EncryptedProperties.KeyManagement;
using EfCore.EncryptedProperties.Metadata;
using EfCore.EncryptedProperties.Providers;
using EfCore.EncryptedProperties.Serialization;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Hosting;

namespace EfCore.EncryptedProperties.Extensions;

public static class EncryptedPropertiesServiceCollectionExtensions
{
    public static IServiceCollection AddEncryptedProperties(
        this IServiceCollection services,
        Action<EncryptedPropertiesServiceBuilder> configure)
    {
        ArgumentNullException.ThrowIfNull(services);
        ArgumentNullException.ThrowIfNull(configure);

        var options = new EncryptedPropertiesOptions();
        var builder = new EncryptedPropertiesServiceBuilder(services, options);

        configure(builder);
        builder.Validate();

        services.RemoveAll<EncryptedPropertiesOptions>();
        services.RemoveAll<IValueSerializer>();
        services.RemoveAll<IKeyChainManager>();
        services.RemoveAll<IEncryptedPropertyCryptor>();
        services.RemoveAll<EncryptedPropertyStateTracker>();
        services.RemoveAll<EncryptedPropertyModelCache>();
        services.RemoveAll<EncryptedPropertiesSaveChangesInterceptor>();
        services.RemoveAll<EncryptedPropertiesMaterializationInterceptor>();

        services.AddLogging();
        services.AddSingleton(options);
        services.AddSingleton<IValueSerializer, ValueSerializer>();
        services.AddSingleton<IKeyChainManager, KeyChainManager>();
        services.AddSingleton<IEncryptedPropertyCryptor, EncryptedPropertyCryptor>();
        services.AddScoped<EncryptedPropertyStateTracker>();
        services.AddSingleton<EncryptedPropertyModelCache>();
        services.AddSingleton<EncryptedPropertiesSaveChangesInterceptor>();
        services.AddSingleton<EncryptedPropertiesMaterializationInterceptor>();

        RemoveKeyChainPreloadHostedService(services);
        if (builder.PreloadOnStartup)
            services.AddSingleton<IHostedService, KeyChainPreloadHostedService>();

        return services;
    }

    private static void RemoveKeyChainPreloadHostedService(IServiceCollection services)
    {
        for (var i = services.Count - 1; i >= 0; i--)
        {
            var descriptor = services[i];
            if (descriptor.ServiceType == typeof(IHostedService)
                && descriptor.ImplementationType == typeof(KeyChainPreloadHostedService))
            {
                services.RemoveAt(i);
            }
        }
    }
}

public sealed class EncryptedPropertiesServiceBuilder
{
    private readonly IServiceCollection _services;
    private readonly EncryptedPropertiesOptions _options;
    private bool _rsaKeyProviderConfigured;
    private bool _keyChainStorageConfigured;
    internal bool PreloadOnStartup { get; private set; }

    internal EncryptedPropertiesServiceBuilder(
        IServiceCollection services,
        EncryptedPropertiesOptions options)
    {
        _services = services;
        _options = options;
    }

    public EncryptedPropertiesServiceBuilder WithInMemoryRsaKeyProvider(RSA rsa, string keyId)
    {
        ArgumentNullException.ThrowIfNull(rsa);
        ThrowIfNullOrWhiteSpace(keyId);

        ReplaceSingleton<IRsaKeyProvider>(new InMemoryRsaKeyProvider(rsa, keyId));
        _rsaKeyProviderConfigured = true;
        return this;
    }

    public EncryptedPropertiesServiceBuilder WithFileRsaKeyProvider(
        string filePath,
        string keyId,
        int keySizeInBits = 2048)
    {
        ThrowIfNullOrWhiteSpace(filePath);
        ThrowIfNullOrWhiteSpace(keyId);

        ReplaceSingleton<IRsaKeyProvider>(new FileRsaKeyProvider(filePath, keyId, keySizeInBits));
        _rsaKeyProviderConfigured = true;
        return this;
    }

    public EncryptedPropertiesServiceBuilder WithFileRsaKeyRingProvider(
        Action<FileRsaKeyRingProviderOptions> configure)
    {
        ArgumentNullException.ThrowIfNull(configure);

        var options = new FileRsaKeyRingProviderOptions();
        configure(options);

        ReplaceSingleton<IRsaKeyProvider>(new FileRsaKeyRingProvider(options));
        _rsaKeyProviderConfigured = true;
        return this;
    }

    public EncryptedPropertiesServiceBuilder WithAzureKeyVaultRsaKeyProvider(
        Uri keyVaultKeyUri,
        TokenCredential credential)
    {
        ArgumentNullException.ThrowIfNull(keyVaultKeyUri);
        ArgumentNullException.ThrowIfNull(credential);

        ReplaceSingleton<IRsaKeyProvider>(new AzureKeyVaultRsaKeyProvider(keyVaultKeyUri, credential));
        _rsaKeyProviderConfigured = true;
        return this;
    }

    public EncryptedPropertiesServiceBuilder WithX509StoreRsaKeyProvider(
        Action<X509StoreRsaKeyProviderOptions> configure)
    {
        ArgumentNullException.ThrowIfNull(configure);

        var options = new X509StoreRsaKeyProviderOptions();
        configure(options);

        ReplaceSingleton<IRsaKeyProvider>(new X509StoreRsaKeyProvider(options));
        _rsaKeyProviderConfigured = true;
        return this;
    }

    public EncryptedPropertiesServiceBuilder WithInMemoryKeyChain()
    {
        ReplaceSingleton<IKeyChainStorage>(new InMemoryKeyChainStorage());
        _keyChainStorageConfigured = true;
        return this;
    }

    public EncryptedPropertiesServiceBuilder WithFileKeyChain(string directoryPath)
    {
        ThrowIfNullOrWhiteSpace(directoryPath);

        ReplaceSingleton<IKeyChainStorage>(new FileKeyChainStorage(directoryPath));
        _keyChainStorageConfigured = true;
        return this;
    }

    public EncryptedPropertiesServiceBuilder WithDatabaseKeyChain(
        DbProviderFactory providerFactory,
        string connectionString)
    {
        ArgumentNullException.ThrowIfNull(providerFactory);
        ThrowIfNullOrWhiteSpace(connectionString);

        ReplaceSingleton<IKeyChainStorage>(new DatabaseKeyChainStorage(providerFactory, connectionString));
        _keyChainStorageConfigured = true;
        return this;
    }

    public EncryptedPropertiesServiceBuilder WithKeyChainRotation(Action<RotationPolicy> configure)
    {
        ArgumentNullException.ThrowIfNull(configure);

        configure(_options.RotationPolicy);
        return this;
    }

    public EncryptedPropertiesServiceBuilder WithKekCacheLifetime(TimeSpan lifetime)
    {
        if (lifetime < TimeSpan.Zero)
            throw new ArgumentOutOfRangeException(nameof(lifetime), "KEK cache lifetime cannot be negative.");

        _options.KekCacheLifetime = lifetime;
        return this;
    }

    public EncryptedPropertiesServiceBuilder WithKeyChainPreloadOnStartup()
    {
        PreloadOnStartup = true;
        return this;
    }

    internal void Validate()
    {
        if (!_rsaKeyProviderConfigured)
            throw new InvalidOperationException(
                "An RSA key provider must be configured via WithInMemoryRsaKeyProvider, WithFileRsaKeyProvider, WithFileRsaKeyRingProvider, WithAzureKeyVaultRsaKeyProvider, or WithX509StoreRsaKeyProvider.");

        if (!_keyChainStorageConfigured)
            throw new InvalidOperationException(
                "A key chain storage must be configured via WithInMemoryKeyChain, WithFileKeyChain, or WithDatabaseKeyChain.");
    }

    private void ReplaceSingleton<TService>(TService instance)
        where TService : class
    {
        _services.RemoveAll<TService>();
        _services.AddSingleton(instance);
    }

    private static void ThrowIfNullOrWhiteSpace(string value)
    {
        if (string.IsNullOrWhiteSpace(value))
            throw new ArgumentException("Value cannot be null or whitespace.", nameof(value));
    }
}
