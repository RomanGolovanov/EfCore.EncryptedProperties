using System.Security.Cryptography;
using EfCore.EncryptedProperties.Abstractions;

namespace EfCore.EncryptedProperties.Providers;

public sealed class FileRsaKeyRingProvider : IRsaKeyProvider
{
    private const string AlgorithmName = "RSA-OAEP-256";
    private readonly Dictionary<string, RSA> _keys;
    private readonly RSA _currentKey;

    public FileRsaKeyRingProvider(FileRsaKeyRingProviderOptions options)
    {
        ArgumentNullException.ThrowIfNull(options);

        KeyId = ValidateOptions(options);
        _keys = LoadKeys(options, KeyId);
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

        var ciphertext = _currentKey.Encrypt(plaintext, RSAEncryptionPadding.OaepSHA256);
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
            throw new InvalidOperationException($"RSA key '{rsaKeyId}' is not configured in the file key ring.");

        var plaintext = key.Decrypt(ciphertext, RSAEncryptionPadding.OaepSHA256);
        return new ValueTask<byte[]>(plaintext);
    }

    private static string ValidateOptions(FileRsaKeyRingProviderOptions options)
    {
        if (string.IsNullOrWhiteSpace(options.CurrentKeyId))
            throw new ArgumentException("Current RSA key ID cannot be null or whitespace.", nameof(options));

        if (options.KeySizeInBits <= 0)
            throw new ArgumentOutOfRangeException(nameof(options.KeySizeInBits), "RSA key size must be positive.");

        var keyIds = new HashSet<string>(StringComparer.Ordinal);
        var currentKeyConfigured = false;

        foreach (var configuredKey in options.Keys)
        {
            if (string.IsNullOrWhiteSpace(configuredKey.KeyId))
                throw new ArgumentException("RSA key ID cannot be null or whitespace.", nameof(options));

            if (string.IsNullOrWhiteSpace(configuredKey.FilePath))
                throw new ArgumentException("RSA key file path cannot be null or whitespace.", nameof(options));

            if (!keyIds.Add(configuredKey.KeyId))
                throw new InvalidOperationException($"RSA key '{configuredKey.KeyId}' is configured more than once.");

            if (string.Equals(configuredKey.KeyId, options.CurrentKeyId, StringComparison.Ordinal))
                currentKeyConfigured = true;
        }

        if (!currentKeyConfigured)
            throw new InvalidOperationException($"Current RSA key '{options.CurrentKeyId}' is not configured in the file key ring.");

        return options.CurrentKeyId;
    }

    private static Dictionary<string, RSA> LoadKeys(
        FileRsaKeyRingProviderOptions options,
        string currentKeyId)
    {
        var keys = new Dictionary<string, RSA>(StringComparer.Ordinal);

        foreach (var configuredKey in options.Keys)
        {
            keys.Add(
                configuredKey.KeyId,
                LoadKey(
                    configuredKey.FilePath,
                    configuredKey.KeyId,
                    currentKeyId,
                    options.KeySizeInBits));
        }

        return keys;
    }

    private static RSA LoadKey(
        string filePath,
        string keyId,
        string currentKeyId,
        int keySizeInBits)
    {
        if (File.Exists(filePath))
        {
            var rsa = RSA.Create();
            rsa.ImportFromPem(File.ReadAllText(filePath));
            return rsa;
        }

        if (!string.Equals(keyId, currentKeyId, StringComparison.Ordinal))
            throw new InvalidOperationException($"RSA key file '{filePath}' for historical key '{keyId}' was not found.");

        var currentKey = RSA.Create(keySizeInBits);
        var dir = Path.GetDirectoryName(filePath);
        if (!string.IsNullOrEmpty(dir))
            Directory.CreateDirectory(dir);

        File.WriteAllText(filePath, currentKey.ExportRSAPrivateKeyPem());
        return currentKey;
    }
}
