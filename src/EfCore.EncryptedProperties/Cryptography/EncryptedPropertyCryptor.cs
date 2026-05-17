using System.Security.Cryptography;
using System.Text;
using EfCore.EncryptedProperties.Abstractions;
using EfCore.EncryptedProperties.Configuration;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;

namespace EfCore.EncryptedProperties.Cryptography;

internal sealed class EncryptedPropertyCryptor : IEncryptedPropertyCryptor
{
    private readonly IKeyChainManager _keyChainManager;
    private readonly IValueSerializer _serializer;
    private readonly ILogger<EncryptedPropertyCryptor> _logger;

    public EncryptedPropertyCryptor(
        IKeyChainManager keyChainManager,
        IValueSerializer serializer,
        ILogger<EncryptedPropertyCryptor>? logger = null)
    {
        _keyChainManager = keyChainManager;
        _serializer = serializer;
        _logger = logger ?? NullLogger<EncryptedPropertyCryptor>.Instance;
    }

    public async ValueTask<string?> EncryptAsync(
        object? value,
        EncryptedPropertyContext context,
        CancellationToken cancellationToken = default)
    {
        if (value is null)
            return null;

        var plaintext = _serializer.Serialize(value, value.GetType());
        var kek = await _keyChainManager.GetActiveKeyAsync(context.Purpose, cancellationToken);
        var cek = CekGenerator.Generate();

        try
        {
            var (wrappedCek, kwIv, kwTag) = AesGcmKeyWrapper.WrapKey(kek.Key, cek);

            var header = new JweHeader
            {
                Alg = "A256GCMKW",
                Enc = "A256GCM",
                Kid = kek.KeyId,
                Iv = Base64Url.Encode(kwIv),
                Tag = Base64Url.Encode(kwTag)
            };

            var headerJson = header.ToJson();
            var headerB64 = Base64Url.Encode(Encoding.UTF8.GetBytes(headerJson));
            var aad = Encoding.ASCII.GetBytes(headerB64);

            var (ciphertext, contentTag, contentIv) = AesGcmEncryptor.Encrypt(cek, plaintext, aad);

            return JweCompactSerializer.Serialize(header, wrappedCek, contentIv, ciphertext, contentTag);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(cek);
        }
    }

    public async ValueTask<object?> DecryptAsync(
        string? payload,
        Type targetType,
        EncryptedPropertyContext context,
        CancellationToken cancellationToken = default)
    {
        if (string.IsNullOrEmpty(payload))
            return null;

        string? keyId = null;

        try
        {
            var components = JweCompactSerializer.Deserialize(payload);
            keyId = components.Header.Kid;

            if (components.Header.Alg != "A256GCMKW")
                throw new CryptographicException($"Unsupported key wrap algorithm: {components.Header.Alg}");

            if (components.Header.Enc != "A256GCM")
                throw new CryptographicException($"Unsupported content encryption: {components.Header.Enc}");

            if (components.Header.Iv is null || components.Header.Tag is null)
                throw new CryptographicException("JWE header missing key-wrap iv or tag for A256GCMKW.");

            var kek = await _keyChainManager.GetKeyForDecryptAsync(components.Header.Kid, cancellationToken);

            var kwIv = Base64Url.Decode(components.Header.Iv);
            var kwTag = Base64Url.Decode(components.Header.Tag);
            var cek = AesGcmKeyWrapper.UnwrapKey(kek.Key, components.WrappedCek, kwIv, kwTag);

            try
            {
                var aad = Encoding.ASCII.GetBytes(components.RawHeaderB64);
                var plaintext = AesGcmEncryptor.Decrypt(cek, components.Ciphertext, components.Tag, components.Iv, aad);
                return _serializer.Deserialize(plaintext, targetType);
            }
            finally
            {
                CryptographicOperations.ZeroMemory(cek);
            }
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            LogDecryptionFailed(ex, context, targetType, keyId);
            throw;
        }
    }

    private void LogDecryptionFailed(
        Exception exception,
        EncryptedPropertyContext context,
        Type targetType,
        string? keyId)
    {
        _logger.LogError(
            EncryptedPropertiesEventIds.DecryptionFailed,
            exception,
            "Failed to decrypt encrypted property {EntityTypeName}.{PropertyName} for purpose {Purpose} as {TargetType} with KEK {KeyId}.",
            context.EntityTypeName ?? "(unknown entity)",
            context.PropertyName ?? "(unknown property)",
            context.Purpose,
            targetType.FullName ?? targetType.Name,
            keyId ?? "(unknown)");
    }
}
