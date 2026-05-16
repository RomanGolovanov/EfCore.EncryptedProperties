namespace EfCore.EncryptedProperties.Abstractions;

public interface IRsaKeyProvider
{
    string KeyId { get; }
    string Algorithm { get; }

    ValueTask<RsaKeyWrapResult> WrapKeyAsync(
        byte[] plaintext,
        CancellationToken cancellationToken = default);

    ValueTask<byte[]> UnwrapKeyAsync(
        byte[] ciphertext,
        string rsaKeyId,
        CancellationToken cancellationToken = default);
}
