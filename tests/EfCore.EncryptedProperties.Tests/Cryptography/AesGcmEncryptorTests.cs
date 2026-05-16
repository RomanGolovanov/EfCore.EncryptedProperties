using System.Security.Cryptography;
using EfCore.EncryptedProperties.Cryptography;

namespace EfCore.EncryptedProperties.Tests.Cryptography;

public class AesGcmEncryptorTests
{
    [Fact]
    public void Encrypt_Decrypt_RoundTrip()
    {
        var key = RandomNumberGenerator.GetBytes(32);
        var plaintext = "Hello, World!"u8.ToArray();
        var aad = "header"u8.ToArray();

        var (ciphertext, tag, iv) = AesGcmEncryptor.Encrypt(key, plaintext, aad);
        var decrypted = AesGcmEncryptor.Decrypt(key, ciphertext, tag, iv, aad);

        Assert.Equal(plaintext, decrypted);
    }

    [Fact]
    public void Encrypt_ProducesDifferentIvEachTime()
    {
        var key = RandomNumberGenerator.GetBytes(32);
        var plaintext = "test"u8.ToArray();
        var aad = "aad"u8.ToArray();

        var (_, _, iv1) = AesGcmEncryptor.Encrypt(key, plaintext, aad);
        var (_, _, iv2) = AesGcmEncryptor.Encrypt(key, plaintext, aad);

        Assert.NotEqual(iv1, iv2);
    }

    [Fact]
    public void Decrypt_WrongKey_Throws()
    {
        var key = RandomNumberGenerator.GetBytes(32);
        var wrongKey = RandomNumberGenerator.GetBytes(32);
        var plaintext = "secret"u8.ToArray();
        var aad = "aad"u8.ToArray();

        var (ciphertext, tag, iv) = AesGcmEncryptor.Encrypt(key, plaintext, aad);

        Assert.ThrowsAny<CryptographicException>(() =>
            AesGcmEncryptor.Decrypt(wrongKey, ciphertext, tag, iv, aad));
    }

    [Fact]
    public void Decrypt_WrongAad_Throws()
    {
        var key = RandomNumberGenerator.GetBytes(32);
        var plaintext = "secret"u8.ToArray();
        var aad = "correct"u8.ToArray();
        var wrongAad = "wrong"u8.ToArray();

        var (ciphertext, tag, iv) = AesGcmEncryptor.Encrypt(key, plaintext, aad);

        Assert.ThrowsAny<CryptographicException>(() =>
            AesGcmEncryptor.Decrypt(key, ciphertext, tag, iv, wrongAad));
    }

    [Fact]
    public void Encrypt_EmptyPlaintext()
    {
        var key = RandomNumberGenerator.GetBytes(32);
        var plaintext = Array.Empty<byte>();
        var aad = "aad"u8.ToArray();

        var (ciphertext, tag, iv) = AesGcmEncryptor.Encrypt(key, plaintext, aad);
        var decrypted = AesGcmEncryptor.Decrypt(key, ciphertext, tag, iv, aad);

        Assert.Empty(decrypted);
    }
}
