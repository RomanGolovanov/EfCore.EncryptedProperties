using System.Security.Cryptography;

namespace EfCore.EncryptedProperties.Cryptography;

internal static class AesGcmEncryptor
{
    private const int IvSizeBytes = 12;
    private const int TagSizeBytes = 16;

    public static (byte[] Ciphertext, byte[] Tag, byte[] Iv) Encrypt(byte[] key, byte[] plaintext, byte[] aad)
    {
        var iv = RandomNumberGenerator.GetBytes(IvSizeBytes);
        var ciphertext = new byte[plaintext.Length];
        var tag = new byte[TagSizeBytes];

        using var aesGcm = new AesGcm(key, TagSizeBytes);
        aesGcm.Encrypt(iv, plaintext, ciphertext, tag, aad);

        return (ciphertext, tag, iv);
    }

    public static byte[] Decrypt(byte[] key, byte[] ciphertext, byte[] tag, byte[] iv, byte[] aad)
    {
        var plaintext = new byte[ciphertext.Length];

        using var aesGcm = new AesGcm(key, TagSizeBytes);
        aesGcm.Decrypt(iv, ciphertext, tag, plaintext, aad);

        return plaintext;
    }
}
