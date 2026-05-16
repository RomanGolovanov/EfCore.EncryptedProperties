using System.Security.Cryptography;

namespace EfCore.EncryptedProperties.Cryptography;

internal static class AesGcmKeyWrapper
{
    private const int IvSizeBytes = 12;
    private const int TagSizeBytes = 16;

    public static (byte[] WrappedKey, byte[] Iv, byte[] Tag) WrapKey(byte[] kek, byte[] plaintext)
    {
        var iv = RandomNumberGenerator.GetBytes(IvSizeBytes);
        var wrappedKey = new byte[plaintext.Length];
        var tag = new byte[TagSizeBytes];

        using var aesGcm = new AesGcm(kek, TagSizeBytes);
        aesGcm.Encrypt(iv, plaintext, wrappedKey, tag);

        return (wrappedKey, iv, tag);
    }

    public static byte[] UnwrapKey(byte[] kek, byte[] wrappedKey, byte[] iv, byte[] tag)
    {
        var plaintext = new byte[wrappedKey.Length];

        using var aesGcm = new AesGcm(kek, TagSizeBytes);
        aesGcm.Decrypt(iv, wrappedKey, tag, plaintext);

        return plaintext;
    }
}
