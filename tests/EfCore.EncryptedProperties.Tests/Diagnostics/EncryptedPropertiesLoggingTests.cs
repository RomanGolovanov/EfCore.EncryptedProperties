using System.Collections.Concurrent;
using System.Security.Cryptography;
using EfCore.EncryptedProperties.Abstractions;
using EfCore.EncryptedProperties.Configuration;
using EfCore.EncryptedProperties.Cryptography;
using EfCore.EncryptedProperties.Extensions;
using EfCore.EncryptedProperties.KeyManagement;
using EfCore.EncryptedProperties.Providers;
using EfCore.EncryptedProperties.Serialization;
using EfCore.EncryptedProperties.Testing;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;

namespace EfCore.EncryptedProperties.Tests.Diagnostics;

public class EncryptedPropertiesLoggingTests
{
    [Fact]
    public async Task GetActiveKeyAsync_LogsKeyCreated()
    {
        using var loggerFactory = CreateLoggerFactory(out var loggerProvider);
        using var rsa = RSA.Create(2048);
        var storage = new InMemoryKeyChainStorage();
        var manager = new KeyChainManager(
            storage,
            new InMemoryRsaKeyProvider(rsa, "rsa-v1"),
            new EncryptedPropertiesOptions(),
            loggerFactory.CreateLogger<KeyChainManager>());

        var key = await manager.GetActiveKeyAsync("default");

        var entry = Assert.Single(loggerProvider.Find(EncryptedPropertiesEventIds.KeyCreated));
        Assert.Equal(LogLevel.Information, entry.LogLevel);
        Assert.Equal("default", entry.GetValue<string>("Purpose"));
        Assert.Equal(key.KeyId, entry.GetValue<Guid>("KeyId").ToString());
        Assert.Equal("rsa-v1", entry.GetValue<string>("RsaKeyId"));
        AssertNoKeyMaterial(entry, key.Key);
    }

    [Fact]
    public async Task GetActiveKeyAsync_LogsKeyRotated()
    {
        using var loggerFactory = CreateLoggerFactory(out var loggerProvider);
        using var rsa = RSA.Create(2048);
        var storage = new InMemoryKeyChainStorage();
        var options = new EncryptedPropertiesOptions { KekCacheLifetime = TimeSpan.Zero };
        options.RotationPolicy.KeyRotateAfter = TimeSpan.Zero;
        var manager = new KeyChainManager(
            storage,
            new InMemoryRsaKeyProvider(rsa, "rsa-v1"),
            options,
            loggerFactory.CreateLogger<KeyChainManager>());

        var oldKey = await manager.GetActiveKeyAsync("default");
        await Task.Delay(10);
        var newKey = await manager.GetActiveKeyAsync("default");

        Assert.NotEqual(oldKey.KeyId, newKey.KeyId);
        var entry = Assert.Single(loggerProvider.Find(EncryptedPropertiesEventIds.KeyRotated));
        Assert.Equal(LogLevel.Information, entry.LogLevel);
        Assert.Equal("default", entry.GetValue<string>("Purpose"));
        Assert.Equal(oldKey.KeyId, entry.GetValue<Guid>("OldKeyId").ToString());
        Assert.Equal(newKey.KeyId, entry.GetValue<Guid>("NewKeyId").ToString());
        AssertNoKeyMaterial(entry, oldKey.Key);
        AssertNoKeyMaterial(entry, newKey.Key);
    }

    [Fact]
    public async Task PreloadAsync_LogsFailureAndRethrows()
    {
        using var loggerFactory = CreateLoggerFactory(out var loggerProvider);
        using var rsa = RSA.Create(2048);
        var storage = new InMemoryKeyChainStorage();
        var sourceManager = new KeyChainManager(
            storage,
            new InMemoryRsaKeyProvider(rsa, "rsa-v1"),
            new EncryptedPropertiesOptions());
        var key = await sourceManager.GetActiveKeyAsync("default");

        var manager = new KeyChainManager(
            storage,
            new FailingUnwrapRsaKeyProvider(),
            new EncryptedPropertiesOptions(),
            loggerFactory.CreateLogger<KeyChainManager>());

        var ex = await Assert.ThrowsAsync<InvalidOperationException>(() => manager.PreloadAsync().AsTask());
        Assert.Contains("unwrap failed", ex.Message);

        var entry = Assert.Single(loggerProvider.Find(EncryptedPropertiesEventIds.KeyPreloadFailed));
        Assert.Equal(LogLevel.Error, entry.LogLevel);
        Assert.Equal("default", entry.GetValue<string>("Purpose"));
        Assert.Equal(key.KeyId, entry.GetValue<Guid>("KeyId").ToString());
        Assert.Equal("rsa-v1", entry.GetValue<string>("RsaKeyId"));
    }

    [Fact]
    public async Task DecryptAsync_LogsFailureWithoutPayload()
    {
        using var loggerFactory = CreateLoggerFactory(out var loggerProvider);
        using var rsa = RSA.Create(2048);
        var keyChainManager = new KeyChainManager(
            new InMemoryKeyChainStorage(),
            new InMemoryRsaKeyProvider(rsa, "rsa-v1"),
            new EncryptedPropertiesOptions());
        var cryptor = new EncryptedPropertyCryptor(
            keyChainManager,
            new ValueSerializer(),
            loggerFactory.CreateLogger<EncryptedPropertyCryptor>());
        var payload = "not-a-jwe-payload-containing-secret@example.com";

        await Assert.ThrowsAnyAsync<Exception>(() =>
            cryptor.DecryptAsync(
                payload,
                typeof(string),
                new EncryptedPropertyContext
                {
                    Purpose = "email",
                    EntityTypeName = "Customer",
                    PropertyName = "Email"
                }).AsTask());

        var entry = Assert.Single(loggerProvider.Find(EncryptedPropertiesEventIds.DecryptionFailed));
        Assert.Equal(LogLevel.Error, entry.LogLevel);
        Assert.Equal("Customer", entry.GetValue<string>("EntityTypeName"));
        Assert.Equal("Email", entry.GetValue<string>("PropertyName"));
        Assert.Equal("email", entry.GetValue<string>("Purpose"));
        Assert.Equal(typeof(string).FullName, entry.GetValue<string>("TargetType"));
        Assert.DoesNotContain(payload, entry.Message, StringComparison.Ordinal);
        Assert.DoesNotContain(entry.State, pair => string.Equals(payload, pair.Value?.ToString(), StringComparison.Ordinal));
    }

    [Fact]
    public async Task SaveChanges_LogsEncryptedModelDiscoveryOnce()
    {
        var loggerProvider = new TestLoggerProvider();
        var dbName = Guid.NewGuid().ToString();
        var services = new ServiceCollection();
        services.AddLogging(builder =>
        {
            builder.ClearProviders();
            builder.AddProvider(loggerProvider);
            builder.SetMinimumLevel(LogLevel.Debug);
        });
        services.AddEncryptedPropertiesForTesting();
        services.AddDbContext<DiagnosticsDbContext>((sp, builder) =>
        {
            builder.UseInMemoryDatabase(dbName);
            builder.UseEncryptedPropertiesForTesting(sp);
        });

        await using var provider = services.BuildServiceProvider();
        await using var scope = provider.CreateAsyncScope();
        var context = scope.ServiceProvider.GetRequiredService<DiagnosticsDbContext>();

        context.Customers.Add(new DiagnosticsCustomer { Id = Guid.NewGuid(), Email = "first@example.com" });
        await context.SaveChangesAsync();

        context.Customers.Add(new DiagnosticsCustomer { Id = Guid.NewGuid(), Email = "second@example.com" });
        await context.SaveChangesAsync();

        var modelEntry = Assert.Single(loggerProvider.Find(EncryptedPropertiesEventIds.EncryptedPropertyModelDiscovered));
        Assert.Equal(LogLevel.Information, modelEntry.LogLevel);
        Assert.Equal(1, modelEntry.GetValue<int>("EncryptedPropertyCount"));

        var propertyEntry = Assert.Single(loggerProvider.Find(EncryptedPropertiesEventIds.EncryptedPropertyDiscovered));
        Assert.Equal(LogLevel.Debug, propertyEntry.LogLevel);
        Assert.Equal(typeof(DiagnosticsCustomer).FullName, propertyEntry.GetValue<string>("EntityTypeName"));
        Assert.Equal(nameof(DiagnosticsCustomer.Email), propertyEntry.GetValue<string>("PropertyName"));
        Assert.Equal("default", propertyEntry.GetValue<string>("Purpose"));
    }

    private static LoggerFactory CreateLoggerFactory(out TestLoggerProvider loggerProvider)
    {
        loggerProvider = new TestLoggerProvider();
        return new LoggerFactory([loggerProvider]);
    }

    private static void AssertNoKeyMaterial(LogEntry entry, byte[] key)
    {
        Assert.DoesNotContain(entry.State, pair => pair.Value is byte[]);

        var logText = entry.Message + " " + string.Join(" ", entry.State.Select(pair => $"{pair.Key}:{pair.Value}"));
        Assert.DoesNotContain(Convert.ToBase64String(key), logText, StringComparison.Ordinal);
        Assert.DoesNotContain(BitConverter.ToString(key), logText, StringComparison.Ordinal);
    }

    private sealed class DiagnosticsDbContext : DbContext
    {
        public DiagnosticsDbContext(DbContextOptions<DiagnosticsDbContext> options) : base(options)
        {
        }

        public DbSet<DiagnosticsCustomer> Customers => Set<DiagnosticsCustomer>();

        protected override void OnModelCreating(ModelBuilder modelBuilder)
        {
            modelBuilder.Entity<DiagnosticsCustomer>(entity =>
            {
                entity.HasKey(e => e.Id);
                entity.Property(e => e.Email).IsEncrypted();
            });
        }
    }

    private sealed class DiagnosticsCustomer
    {
        public Guid Id { get; set; }
        public string Email { get; set; } = string.Empty;
    }

    private sealed class FailingUnwrapRsaKeyProvider : IRsaKeyProvider
    {
        public string KeyId => "failing-rsa";
        public string Algorithm => "RSA-OAEP-256";

        public ValueTask<RsaKeyWrapResult> WrapKeyAsync(
            byte[] plaintext,
            CancellationToken cancellationToken = default)
        {
            throw new NotSupportedException();
        }

        public ValueTask<byte[]> UnwrapKeyAsync(
            byte[] ciphertext,
            string rsaKeyId,
            CancellationToken cancellationToken = default)
        {
            throw new InvalidOperationException("unwrap failed");
        }
    }
}

internal sealed class TestLoggerProvider : ILoggerProvider
{
    private readonly ConcurrentQueue<LogEntry> _entries = new();

    public IReadOnlyList<LogEntry> Find(EventId eventId)
    {
        return _entries.Where(entry => entry.EventId.Id == eventId.Id).ToList();
    }

    public ILogger CreateLogger(string categoryName)
    {
        return new TestLogger(categoryName, _entries);
    }

    public void Dispose()
    {
    }

    private sealed class TestLogger : ILogger
    {
        private readonly string _categoryName;
        private readonly ConcurrentQueue<LogEntry> _entries;

        public TestLogger(string categoryName, ConcurrentQueue<LogEntry> entries)
        {
            _categoryName = categoryName;
            _entries = entries;
        }

        public IDisposable? BeginScope<TState>(TState state)
            where TState : notnull
        {
            return null;
        }

        public bool IsEnabled(LogLevel logLevel)
        {
            return logLevel != LogLevel.None;
        }

        public void Log<TState>(
            LogLevel logLevel,
            EventId eventId,
            TState state,
            Exception? exception,
            Func<TState, Exception?, string> formatter)
        {
            var structuredState = state as IEnumerable<KeyValuePair<string, object?>>
                ?? Array.Empty<KeyValuePair<string, object?>>();

            _entries.Enqueue(new LogEntry(
                _categoryName,
                logLevel,
                eventId,
                formatter(state, exception),
                exception,
                structuredState.ToArray()));
        }
    }
}

internal sealed record LogEntry(
    string Category,
    LogLevel LogLevel,
    EventId EventId,
    string Message,
    Exception? Exception,
    IReadOnlyList<KeyValuePair<string, object?>> State)
{
    public TValue? GetValue<TValue>(string key)
    {
        var value = State.First(pair => string.Equals(pair.Key, key, StringComparison.Ordinal)).Value;
        return value is null ? default : (TValue)value;
    }
}
