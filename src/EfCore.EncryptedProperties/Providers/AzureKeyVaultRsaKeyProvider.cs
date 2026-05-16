using System.Collections.Concurrent;
using System.Security.Cryptography;
using Azure.Core;
using Azure.Security.KeyVault.Keys;
using Azure.Security.KeyVault.Keys.Cryptography;
using EfCore.EncryptedProperties.Abstractions;

namespace EfCore.EncryptedProperties.Providers;

public sealed class AzureKeyVaultRsaKeyProvider : IRsaKeyProvider
{
    private readonly ConcurrentDictionary<string, CryptographyClient> _cryptoClients = new(StringComparer.Ordinal);
    private readonly TokenCredential _credential;
    private readonly KeyClient _keyClient;
    private readonly string _keyName;

    public AzureKeyVaultRsaKeyProvider(Uri keyVaultKeyUri, TokenCredential credential)
    {
        ArgumentNullException.ThrowIfNull(keyVaultKeyUri);
        ArgumentNullException.ThrowIfNull(credential);

        _credential = credential;
        var vaultUri = new Uri(keyVaultKeyUri.GetLeftPart(UriPartial.Authority));
        _keyClient = new KeyClient(vaultUri, credential);

        var segments = keyVaultKeyUri.AbsolutePath.Split('/', StringSplitOptions.RemoveEmptyEntries);
        if (segments.Length < 2 || !string.Equals(segments[0], "keys", StringComparison.OrdinalIgnoreCase))
            throw new ArgumentException("Key Vault key URI must have the form 'https://{vault}/keys/{key-name}' or 'https://{vault}/keys/{key-name}/{version}'.", nameof(keyVaultKeyUri));

        _keyName = segments[1];
        KeyId = _keyName;
    }

    public string KeyId { get; }
    public string Algorithm => "RSA-OAEP-256";

    public async ValueTask<RsaKeyWrapResult> WrapKeyAsync(byte[] plaintext, CancellationToken cancellationToken = default)
    {
        var response = await _keyClient.GetKeyAsync(_keyName, cancellationToken: cancellationToken);
        using var publicKey = response.Value.Key.ToRSA();
        var ciphertext = publicKey.Encrypt(plaintext, RSAEncryptionPadding.OaepSHA256);
        return new RsaKeyWrapResult(ciphertext, response.Value.Id.ToString(), Algorithm);
    }

    public async ValueTask<byte[]> UnwrapKeyAsync(
        byte[] ciphertext,
        string rsaKeyId,
        CancellationToken cancellationToken = default)
    {
        if (string.IsNullOrWhiteSpace(rsaKeyId))
            throw new ArgumentException("RSA key ID cannot be null or whitespace.", nameof(rsaKeyId));

        var cryptoClient = _cryptoClients.GetOrAdd(
            rsaKeyId,
            keyId => new CryptographyClient(new Uri(keyId), _credential));

        var result = await cryptoClient.UnwrapKeyAsync(
            KeyWrapAlgorithm.RsaOaep256,
            ciphertext,
            cancellationToken);
        return result.Key;
    }
}
