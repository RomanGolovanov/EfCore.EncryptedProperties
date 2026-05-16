using System.Security.Cryptography;
using EfCore.EncryptedProperties.Configuration;
using EfCore.EncryptedProperties.Cryptography;
using EfCore.EncryptedProperties.KeyManagement;
using EfCore.EncryptedProperties.Providers;
using EfCore.EncryptedProperties.Serialization;

namespace EfCore.EncryptedProperties.Tests.Cryptography;

public class EncryptedPropertyCryptorTests
{
    private readonly EncryptedPropertyCryptor _cryptor;
    private readonly EncryptedPropertyContext _context;

    public EncryptedPropertyCryptorTests()
    {
        var rsa = RSA.Create(2048);
        var rsaProvider = new InMemoryRsaKeyProvider(rsa, "test-key");
        var storage = new InMemoryKeyChainStorage();
        var options = new EncryptedPropertiesOptions();
        var keyChainManager = new KeyChainManager(storage, rsaProvider, options);
        var serializer = new ValueSerializer();
        _cryptor = new EncryptedPropertyCryptor(keyChainManager, serializer);
        _context = new EncryptedPropertyContext { Purpose = "test" };
    }

    [Fact]
    public async Task EncryptDecrypt_String_RoundTrip()
    {
        var value = "Hello, World!";
        var encrypted = await _cryptor.EncryptAsync(value, _context);
        Assert.NotNull(encrypted);
        Assert.Contains(".", encrypted);

        var decrypted = await _cryptor.DecryptAsync(encrypted, typeof(string), _context);
        Assert.Equal(value, decrypted);
    }

    [Fact]
    public async Task EncryptDecrypt_Int_RoundTrip()
    {
        var value = 42;
        var encrypted = await _cryptor.EncryptAsync(value, _context);
        var decrypted = await _cryptor.DecryptAsync(encrypted, typeof(int), _context);
        Assert.Equal(value, decrypted);
    }

    [Fact]
    public async Task EncryptDecrypt_Guid_RoundTrip()
    {
        var value = Guid.NewGuid();
        var encrypted = await _cryptor.EncryptAsync(value, _context);
        var decrypted = await _cryptor.DecryptAsync(encrypted, typeof(Guid), _context);
        Assert.Equal(value, decrypted);
    }

    [Fact]
    public async Task EncryptDecrypt_Bool_RoundTrip()
    {
        var encrypted = await _cryptor.EncryptAsync(true, _context);
        var decrypted = await _cryptor.DecryptAsync(encrypted, typeof(bool), _context);
        Assert.Equal(true, decrypted);
    }

    [Fact]
    public async Task EncryptDecrypt_DateTime_RoundTrip()
    {
        var value = new DateTime(2025, 6, 15, 10, 30, 0, DateTimeKind.Utc);
        var encrypted = await _cryptor.EncryptAsync(value, _context);
        var decrypted = await _cryptor.DecryptAsync(encrypted, typeof(DateTime), _context);
        Assert.Equal(value, decrypted);
    }

    [Fact]
    public async Task EncryptDecrypt_ByteArray_RoundTrip()
    {
        var value = new byte[] { 1, 2, 3, 4, 5 };
        var encrypted = await _cryptor.EncryptAsync(value, _context);
        var decrypted = await _cryptor.DecryptAsync(encrypted, typeof(byte[]), _context);
        Assert.Equal(value, decrypted);
    }

    [Fact]
    public async Task Encrypt_Null_ReturnsNull()
    {
        var encrypted = await _cryptor.EncryptAsync(null, _context);
        Assert.Null(encrypted);
    }

    [Fact]
    public async Task Decrypt_Null_ReturnsNull()
    {
        var decrypted = await _cryptor.DecryptAsync(null, typeof(string), _context);
        Assert.Null(decrypted);
    }

    [Fact]
    public async Task Decrypt_EmptyString_ReturnsNull()
    {
        var decrypted = await _cryptor.DecryptAsync("", typeof(string), _context);
        Assert.Null(decrypted);
    }

    [Fact]
    public async Task Encrypt_ProducesValidJwe()
    {
        var encrypted = await _cryptor.EncryptAsync("test", _context);
        Assert.NotNull(encrypted);

        var parts = encrypted!.Split('.');
        Assert.Equal(5, parts.Length);

        var components = JweCompactSerializer.Deserialize(encrypted);
        Assert.Equal("A256GCMKW", components.Header.Alg);
        Assert.Equal("A256GCM", components.Header.Enc);
        Assert.NotNull(components.Header.Iv);
        Assert.NotNull(components.Header.Tag);
    }

    [Fact]
    public async Task Encrypt_SameValue_ProducesDifferentCiphertext()
    {
        var encrypted1 = await _cryptor.EncryptAsync("test", _context);
        var encrypted2 = await _cryptor.EncryptAsync("test", _context);

        Assert.NotEqual(encrypted1, encrypted2);
    }
}
