using System.Security.Cryptography;
using EfCore.EncryptedProperties.Abstractions;

namespace EfCore.EncryptedProperties.Providers;

public sealed class FileRsaKeyProvider : IRsaKeyProvider
{
    private readonly RSA _rsa;

    public FileRsaKeyProvider(string filePath, string keyId, int keySizeInBits = 2048)
    {
        KeyId = keyId;

        if (File.Exists(filePath))
        {
            _rsa = RSA.Create();
            _rsa.ImportFromPem(File.ReadAllText(filePath));
        }
        else
        {
            _rsa = RSA.Create(keySizeInBits);
            var dir = Path.GetDirectoryName(filePath);
            if (!string.IsNullOrEmpty(dir))
                Directory.CreateDirectory(dir);
            File.WriteAllText(filePath, _rsa.ExportRSAPrivateKeyPem());
        }
    }

    public string KeyId { get; }
    public string Algorithm => "RSA-OAEP-256";

    public ValueTask<RsaKeyWrapResult> WrapKeyAsync(byte[] plaintext, CancellationToken cancellationToken = default)
    {
        var result = _rsa.Encrypt(plaintext, RSAEncryptionPadding.OaepSHA256);
        return new ValueTask<RsaKeyWrapResult>(new RsaKeyWrapResult(result, KeyId, Algorithm));
    }

    public ValueTask<byte[]> UnwrapKeyAsync(
        byte[] ciphertext,
        string rsaKeyId,
        CancellationToken cancellationToken = default)
    {
        if (!string.Equals(rsaKeyId, KeyId, StringComparison.Ordinal))
            throw new InvalidOperationException($"RSA key '{rsaKeyId}' does not match configured key '{KeyId}'.");

        var result = _rsa.Decrypt(ciphertext, RSAEncryptionPadding.OaepSHA256);
        return new ValueTask<byte[]>(result);
    }
}
