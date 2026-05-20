using System.Security.Cryptography;
using EfCore.EncryptedProperties.Abstractions;

namespace EfCore.EncryptedProperties.Providers;

public sealed class FilePfxRsaKeyRingProvider : IRsaKeyProvider
{
    private const string AlgorithmName = "RSA-OAEP-256";
    private readonly Dictionary<string, PfxRsaKeyMaterial> _keys;
    private readonly PfxRsaKeyMaterial _currentKey;

    public FilePfxRsaKeyRingProvider(FilePfxRsaKeyRingProviderOptions options)
    {
        ArgumentNullException.ThrowIfNull(options);

        KeyId = ValidateOptions(options);
        _keys = LoadKeys(options);
        _currentKey = _keys[KeyId];
    }

    public string KeyId { get; }
    public string Algorithm => AlgorithmName;

    public ValueTask<RsaKeyWrapResult> WrapKeyAsync(
        byte[] plaintext,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(plaintext);
        cancellationToken.ThrowIfCancellationRequested();

        var ciphertext = _currentKey.Rsa.Encrypt(plaintext, RSAEncryptionPadding.OaepSHA256);
        return new ValueTask<RsaKeyWrapResult>(new RsaKeyWrapResult(ciphertext, KeyId, Algorithm));
    }

    public ValueTask<byte[]> UnwrapKeyAsync(
        byte[] ciphertext,
        string rsaKeyId,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(ciphertext);
        if (string.IsNullOrWhiteSpace(rsaKeyId))
            throw new ArgumentException("RSA key ID cannot be null or whitespace.", nameof(rsaKeyId));

        cancellationToken.ThrowIfCancellationRequested();

        if (!_keys.TryGetValue(rsaKeyId, out var key))
            throw new InvalidOperationException($"RSA key '{rsaKeyId}' is not configured in the file PFX key ring.");

        var plaintext = key.Rsa.Decrypt(ciphertext, RSAEncryptionPadding.OaepSHA256);
        return new ValueTask<byte[]>(plaintext);
    }

    private static string ValidateOptions(FilePfxRsaKeyRingProviderOptions options)
    {
        if (string.IsNullOrWhiteSpace(options.CurrentKeyId))
            throw new ArgumentException("Current RSA key ID cannot be null or whitespace.", nameof(options));

        var keyIds = new HashSet<string>(StringComparer.Ordinal);
        var currentKeyConfigured = false;

        foreach (var configuredKey in options.Keys)
        {
            if (string.IsNullOrWhiteSpace(configuredKey.KeyId))
                throw new ArgumentException("RSA key ID cannot be null or whitespace.", nameof(options));

            if (string.IsNullOrWhiteSpace(configuredKey.FilePath))
                throw new ArgumentException("PFX RSA key file path cannot be null or whitespace.", nameof(options));

            if (!keyIds.Add(configuredKey.KeyId))
                throw new InvalidOperationException($"RSA key '{configuredKey.KeyId}' is configured more than once.");

            if (string.Equals(configuredKey.KeyId, options.CurrentKeyId, StringComparison.Ordinal))
                currentKeyConfigured = true;
        }

        if (!currentKeyConfigured)
            throw new InvalidOperationException($"Current RSA key '{options.CurrentKeyId}' is not configured in the file PFX key ring.");

        return options.CurrentKeyId;
    }

    private static Dictionary<string, PfxRsaKeyMaterial> LoadKeys(FilePfxRsaKeyRingProviderOptions options)
    {
        var keys = new Dictionary<string, PfxRsaKeyMaterial>(StringComparer.Ordinal);

        foreach (var configuredKey in options.Keys)
        {
            keys.Add(
                configuredKey.KeyId,
                PfxRsaKeyMaterial.LoadFromFile(
                    configuredKey.FilePath,
                    configuredKey.Password,
                    options.KeyStorageFlags));
        }

        return keys;
    }
}
