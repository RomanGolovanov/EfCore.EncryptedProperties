using System.Security.Cryptography;
using EfCore.EncryptedProperties.Cryptography;

namespace EfCore.EncryptedProperties.Tests.Cryptography;

public class AesGcmKeyWrapperTests
{
    [Fact]
    public void WrapKey_UnwrapKey_RoundTrip()
    {
        var kek = RandomNumberGenerator.GetBytes(32);
        var cek = RandomNumberGenerator.GetBytes(32);

        var (wrappedKey, iv, tag) = AesGcmKeyWrapper.WrapKey(kek, cek);
        var unwrapped = AesGcmKeyWrapper.UnwrapKey(kek, wrappedKey, iv, tag);

        Assert.Equal(cek, unwrapped);
    }

    [Fact]
    public void WrapKey_ProducesDifferentOutputEachTime()
    {
        var kek = RandomNumberGenerator.GetBytes(32);
        var cek = RandomNumberGenerator.GetBytes(32);

        var (wrapped1, iv1, _) = AesGcmKeyWrapper.WrapKey(kek, cek);
        var (wrapped2, iv2, _) = AesGcmKeyWrapper.WrapKey(kek, cek);

        Assert.NotEqual(iv1, iv2);
    }

    [Fact]
    public void UnwrapKey_WrongKek_Throws()
    {
        var kek = RandomNumberGenerator.GetBytes(32);
        var wrongKek = RandomNumberGenerator.GetBytes(32);
        var cek = RandomNumberGenerator.GetBytes(32);

        var (wrappedKey, iv, tag) = AesGcmKeyWrapper.WrapKey(kek, cek);

        Assert.ThrowsAny<CryptographicException>(() =>
            AesGcmKeyWrapper.UnwrapKey(wrongKek, wrappedKey, iv, tag));
    }

    [Fact]
    public void UnwrapKey_TamperedTag_Throws()
    {
        var kek = RandomNumberGenerator.GetBytes(32);
        var cek = RandomNumberGenerator.GetBytes(32);

        var (wrappedKey, iv, tag) = AesGcmKeyWrapper.WrapKey(kek, cek);
        tag[0] ^= 0xFF;

        Assert.ThrowsAny<CryptographicException>(() =>
            AesGcmKeyWrapper.UnwrapKey(kek, wrappedKey, iv, tag));
    }

    [Fact]
    public void WrappedKey_SameLength_AsPlaintext()
    {
        var kek = RandomNumberGenerator.GetBytes(32);
        var cek = RandomNumberGenerator.GetBytes(32);

        var (wrappedKey, _, _) = AesGcmKeyWrapper.WrapKey(kek, cek);

        Assert.Equal(cek.Length, wrappedKey.Length);
    }
}
