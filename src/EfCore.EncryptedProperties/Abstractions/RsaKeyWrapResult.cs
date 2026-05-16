namespace EfCore.EncryptedProperties.Abstractions;

public sealed record RsaKeyWrapResult(
    byte[] Ciphertext,
    string RsaKeyId,
    string Algorithm);
